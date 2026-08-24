package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
)

const childEnvironment = "TOY_CONTAINER_CHILD"
const rootfsEnvironment = "TOY_CONTAINER_ROOTFS"
const cgroupEnvironment = "TOY_CONTAINER_CGROUP"
const networkReadyFDEnvironment = "TOY_CONTAINER_NETWORK_READY_FD"
const memoryLimitBytes = "67108864" // 64 MiB
const taskLimit = "32"
const hostNetworkAddress = "10.200.0.1/24"
const containerNetworkAddress = "10.200.0.2/24"
const containerGateway = "10.200.0.1"

// main selects either the outer-launcher stage or the namespace-init stage.
func main() {
	// The launcher starts a second copy of this executable with this marker.
	// That copy is namespace-init: PID 1 inside the new PID namespace.
	if os.Getenv(childEnvironment) == "1" {
		if err := runNamespaceChild(
			os.Getenv(rootfsEnvironment),
			os.Args[1:],
		); err != nil {
			fmt.Fprintln(os.Stderr, "namespace child failed:", err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) < 4 || os.Args[1] != "--rootfs" {
		fmt.Fprintln(
			os.Stderr,
			"usage: toy-container --rootfs DIRECTORY PROGRAM [ARGUMENT...]",
		)
		os.Exit(2)
	}

	rootfs, err := filepath.Abs(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve root filesystem path:", err)
		os.Exit(1)
	}
	// arg 0 is the program name, arg 1 is the rootfs path, arg 2 is the program name, arg 3 is the program arguments including:
	// /path/to/rootfs /path/to/program arg1 arg2 arg3
	arguments := os.Args[3:]
	fmt.Println("all arguments:", os.Args)
	fmt.Println("root filesystem:", rootfs)
	fmt.Println("program:", arguments[0])
	fmt.Println("program arguments:", arguments[1:])

	if err := runOuter(rootfs, arguments); err != nil { // host process runs this
		fmt.Fprintln(os.Stderr, "outer launcher failed:", err)
		os.Exit(1)
	}
}

// runOuter creates the resource group, launches namespace-init, and reports its resource use.
func runOuter(rootfs string, arguments []string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find current executable: %w", err)
	}
	cgroup, err := os.MkdirTemp("/sys/fs/cgroup", "meshlet-toy-")
	if err != nil {
		return fmt.Errorf("create cgroup (run this launcher with sudo): %w", err)
	}
	defer os.Remove(cgroup)
	if err := configureCgroup(cgroup); err != nil {
		return err
	}

	// create the sync pipe, read end will be a fd in the child's namespace
	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create network readiness pipe: %w", err)
	}
	defer readyReader.Close() // close at end
	defer readyWriter.Close()

	// setup how to run the child process
	command := exec.Command(self, arguments...)
	command.Env = append(
		os.Environ(),
		childEnvironment+"=1",
		rootfsEnvironment+"="+rootfs,
		cgroupEnvironment+"="+cgroup,
		networkReadyFDEnvironment+"=3",
	)

	// ExtraFiles puts the pipe's read end file descriptor 3 in namespace-init.
	// The child blocks on this file descriptor until the outer launcher finishes network setup.
	command.ExtraFiles = []*os.File{readyReader}
	// SysProcAttr passes Linux-specific process-creation options through Go.
	// These flags give the new process separate hostname, PID, mount, and network views.
	command.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNS |
			syscall.CLONE_NEWNET,
	}
	connectTerminal(command) // connect the stdin, stdout, and stderr files to the child



	// run the child, which is put into new namespaces
	if err := command.Start(); err != nil {
		return fmt.Errorf("start namespace child: %w", err)
	}
	fmt.Println("namespace init PID as seen by outer launcher:", command.Process.Pid)
	fmt.Println("cgroup:", cgroup)

	// close the host's copy of the readiness reader in the outer launcher. there are two copies because 
	if err := readyReader.Close(); err != nil {
		return fmt.Errorf("close outer copy of readiness reader: %w", err)
	}

	// configure the network
	hostInterface, err := configureNetwork(command.Process.Pid)
	if err != nil {
		readyWriter.Close() // shutdown the program gracefully
		command.Wait()
		return err
	}
	defer deleteNetworkInterface(hostInterface)

	// signal the network is ready
	if err := signalNetworkReady(readyWriter); err != nil {
		command.Wait()
		return err
	}

	waitErr := command.Wait()
	if err := printCgroupAccounting(cgroup); err != nil {
		return err
	}
	return waitErr
}

// runNamespaceChild prepares the isolated environment and runs the requested application inside it.
func runNamespaceChild(rootfs string, arguments []string) error {
	cgroup := os.Getenv(cgroupEnvironment)
	readyFD := os.Getenv(networkReadyFDEnvironment)
	if rootfs == "" {
		return fmt.Errorf("missing root filesystem path")
	}
	if cgroup == "" {
		return fmt.Errorf("missing cgroup path")
	}
	if readyFD == "" {
		return fmt.Errorf("missing network readiness file descriptor")
	}
	if len(arguments) == 0 {
		return fmt.Errorf("missing application program")
	}

	if err := os.Unsetenv(childEnvironment); err != nil {
		return fmt.Errorf("remove internal child marker: %w", err)
	}
	if err := os.Unsetenv(rootfsEnvironment); err != nil {
		return fmt.Errorf("remove internal root filesystem path: %w", err)
	}
	if err := os.Unsetenv(cgroupEnvironment); err != nil {
		return fmt.Errorf("remove internal cgroup path: %w", err)
	}
	if err := os.Unsetenv(networkReadyFDEnvironment); err != nil {
		return fmt.Errorf("remove internal network readiness descriptor: %w", err)
	}

	// cgroup.procs is a kernel control file, not stored data. Writing 0 attaches
	// this process; applications it starts inherit the same resource group.
	if err := os.WriteFile(
		filepath.Join(cgroup, "cgroup.procs"),
		[]byte("0"),
		0o644,
	); err != nil {
		return fmt.Errorf("join cgroup %s: %w", cgroup, err)
	}

	fmt.Println("namespace init PID inside namespace:", os.Getpid())
	if err := waitForNetworkReady(readyFD); err != nil {
		return err
	}
	fmt.Println("container network ready: eth0 10.200.0.2/24 via 10.200.0.1")

	// Prevent later mount changes in this namespace from propagating back into
	// the outer mount view inherited when this process was created.
	if err := syscall.Mount(
		"",
		"/",
		"",
		syscall.MS_REC|syscall.MS_PRIVATE,
		"",
	); err != nil {
		return fmt.Errorf("make child mounts private: %w", err)
	}

	// Chroot changes the starting point for absolute path lookup: rootfs becomes /.
	if err := syscall.Chroot(rootfs); err != nil {
		return fmt.Errorf("change child root to %s: %w", rootfs, err)
	}
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("change working directory to child root: %w", err)
	}
	fmt.Println("child root changed to selected root filesystem")

	// procfs is a kernel-generated filesystem. Mounted here, /proc describes
	// the processes visible through this process's PID namespace.
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		return fmt.Errorf("mount child proc filesystem: %w", err)
	}
	fmt.Println("child proc filesystem mounted at /proc")

	application := exec.Command(arguments[0], arguments[1:]...)
	connectTerminal(application)

	if err := application.Start(); err != nil {
		return fmt.Errorf("start application: %w", err)
	}

	fmt.Println("application PID inside namespace:", application.Process.Pid)
	return application.Wait()
}

// configureNetwork connects the child's private network namespace to one outer veth endpoint.
// create veth pair
// configure outer end
// move peer to namespace-init
// enter namespace using nsenter
// confgiure inner end
// return the host interface name so
func configureNetwork(namespaceInitPID int) (string, error) {
	hostInterface := fmt.Sprintf("mt%d", namespaceInitPID)
	peerInterface := fmt.Sprintf("mp%d", namespaceInitPID)
	created := false
	defer func() {
		if created {
			deleteNetworkInterface(hostInterface)
		}
	}()

	if err := runLinuxCommand(
		"ip", "link", "add", hostInterface,
		"type", "veth", "peer", "name", peerInterface,
	); err != nil {
		return "", err
	}
	created = true
	if err := runLinuxCommand("ip", "address", "add", hostNetworkAddress, "dev", hostInterface); err != nil {
		return "", err
	}
	if err := runLinuxCommand("ip", "link", "set", hostInterface, "up"); err != nil {
		return "", err
	}
	if err := runLinuxCommand("ip", "link", "set", peerInterface, "netns", strconv.Itoa(namespaceInitPID)); err != nil {
		return "", err
	}

	// nsenter runs each ip command using namespace-init's network namespace.
	inside := func(arguments ...string) error {
		prefix := []string{"--target", strconv.Itoa(namespaceInitPID), "--net", "ip"}
		return runLinuxCommand("nsenter", append(prefix, arguments...)...)
	}

	// checks
	if err := inside("link", "set", peerInterface, "name", "eth0"); err != nil {
		return "", err
	}
	if err := inside("address", "add", containerNetworkAddress, "dev", "eth0"); err != nil {
		return "", err
	}
	if err := inside("link", "set", "lo", "up"); err != nil {
		return "", err
	}
	if err := inside("link", "set", "eth0", "up"); err != nil {
		return "", err
	}
	if err := inside("route", "add", "default", "via", containerGateway, "dev", "eth0"); err != nil {
		return "", err
	}

	created = false
	fmt.Printf("veth: eth0 inside namespace-init <-> %s outside\n", hostInterface)
	return hostInterface, nil
}

// signalNetworkReady releases namespace-init after its interface and routes are configured.
func signalNetworkReady(writer *os.File) error {
	// outer/host process will write a byte to the pipe, signaling the network is ready
	if _, err := writer.Write([]byte{1}); err != nil {
		return fmt.Errorf("signal network readiness: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("close network readiness writer: %w", err)
	}
	return nil
}

// waitForNetworkReady blocks namespace-init until the outer launcher completes network setup.
func waitForNetworkReady(fileDescriptor string) error {
	fd, err := strconv.Atoi(fileDescriptor)
	if err != nil {
		return fmt.Errorf("parse network readiness descriptor: %w", err)
	}
	reader := os.NewFile(uintptr(fd), "network-ready")
	if reader == nil {
		return fmt.Errorf("open network readiness descriptor %d", fd)
	}

	// wait for the outer launcher to send a byte on the pipe, signaling the network is ready
	var signal [1]byte
	_, readErr := io.ReadFull(reader, signal[:])

	// shutdown the child process
	closeErr := reader.Close()
	if readErr != nil {
		return fmt.Errorf("wait for network setup: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close network readiness reader: %w", closeErr)
	}
	return nil
}

// deleteNetworkInterface removes the outer veth endpoint and therefore the connected pair.
func deleteNetworkInterface(interfaceName string) {
	_ = runLinuxCommand("ip", "link", "delete", interfaceName)
}

// runLinuxCommand runs one Linux networking tool and includes its output in any error.
func runLinuxCommand(program string, arguments ...string) error {
	output, err := exec.Command(program, arguments...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("run %s %v: %w: %s", program, arguments, err, output)
	}
	return nil
}

// configureCgroup writes the memory and task ceilings enforced for the container process tree.
func configureCgroup(cgroup string) error {
	for _, limit := range []struct {
		label string
		file  string
		value string
	}{
		{label: "memory", file: "memory.max", value: memoryLimitBytes},
		{label: "tasks", file: "pids.max", value: taskLimit},
	} {
		// Files under /sys/fs/cgroup are the kernel's configuration interface.
		if err := os.WriteFile(
			filepath.Join(cgroup, limit.file),
			[]byte(limit.value),
			0o644,
		); err != nil {
			return fmt.Errorf("set cgroup %s limit: %w", limit.label, err)
		}
		fmt.Printf("cgroup %s limit: %s\n", limit.label, limit.value)
	}
	return nil
}

// printCgroupAccounting prints the CPU, memory, and task usage accumulated by the process tree.
func printCgroupAccounting(cgroup string) error {
	for _, metric := range []struct {
		label string
		file  string
	}{
		{label: "CPU time", file: "cpu.stat"},
		{label: "peak memory in bytes", file: "memory.peak"},
		{label: "peak process count", file: "pids.peak"},
	} {
		value, err := os.ReadFile(filepath.Join(cgroup, metric.file))
		if err != nil {
			return fmt.Errorf("read cgroup %s: %w", metric.file, err)
		}
		fmt.Printf("cgroup %s:\n%s", metric.label, value)
	}
	return nil
}

// connectTerminal lets a child use the launcher's keyboard and terminal output.
func connectTerminal(command *exec.Cmd) {
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
}

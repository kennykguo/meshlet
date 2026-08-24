package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const childEnvironment = "TOY_CONTAINER_CHILD"
const rootfsEnvironment = "TOY_CONTAINER_ROOTFS"
const cgroupEnvironment = "TOY_CONTAINER_CGROUP"
const memoryLimitBytes = "67108864" // 64 MiB
const taskLimit = "32"

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

	command := exec.Command(self, arguments...)
	command.Env = append(
		os.Environ(),
		childEnvironment+"=1",
		rootfsEnvironment+"="+rootfs,
		cgroupEnvironment+"="+cgroup,
	)
	// SysProcAttr passes Linux-specific process-creation options through Go.
	// These flags give the new process separate hostname, PID, and mount views.
	command.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNS,
	}
	connectTerminal(command)

	if err := command.Start(); err != nil {
		return fmt.Errorf("start namespace child: %w", err)
	}

	fmt.Println("namespace init PID as seen by outer launcher:", command.Process.Pid)
	fmt.Println("cgroup:", cgroup)

	waitErr := command.Wait()
	if err := printCgroupAccounting(cgroup); err != nil {
		return err
	}
	return waitErr
}

// runNamespaceChild prepares the isolated environment and runs the requested application inside it.
func runNamespaceChild(rootfs string, arguments []string) error {
	cgroup := os.Getenv(cgroupEnvironment)
	if rootfs == "" {
		return fmt.Errorf("missing root filesystem path")
	}
	if cgroup == "" {
		return fmt.Errorf("missing cgroup path")
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

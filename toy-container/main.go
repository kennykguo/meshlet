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

func main() { // no host process, host process just runs the child process
	// if the child environment is set, run the child function
	if os.Getenv(childEnvironment) == "1" {
		if err := runNamespaceChild( // run by the child process
			os.Getenv(rootfsEnvironment),
			os.Args[1:],
		); err != nil {
			fmt.Fprintln(os.Stderr, "namespace child failed:", err)
			os.Exit(1)
		}
		return
	}

	// if the arguments are not valid, print the usage and exit
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

	if err := runOuter(rootfs, arguments); err != nil {
		fmt.Fprintln(os.Stderr, "outer launcher failed:", err)
		os.Exit(1)
	}
}

// launches the new process in a new namespace
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

	command := exec.Command(self, arguments...)
	command.Env = append(
		os.Environ(),
		childEnvironment+"=1",
		rootfsEnvironment+"="+rootfs,
		cgroupEnvironment+"="+cgroup,
	)
	command.SysProcAttr = &syscall.SysProcAttr{
		// CLONE_NEWUTS: create a new hostname for the container
		// CLONE_NEWPID: create a new PID namespace for the container
		// CLONE_NEWNS: create a new mount namespace for the container
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

// child runs this
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

	// Writing 0 moves the writing process into this cgroup. The application
	// started later inherits the same cgroup membership.
	if err := os.WriteFile(
		filepath.Join(cgroup, "cgroup.procs"),
		[]byte("0"),
		0o644,
	); err != nil {
		return fmt.Errorf("join cgroup %s: %w", cgroup, err)
	}

	fmt.Println("namespace init PID inside namespace:", os.Getpid())

	// make child mounts private
	if err := syscall.Mount(
		"",
		"/",
		"",
		syscall.MS_REC|syscall.MS_PRIVATE,
		"",
	); err != nil {
		return fmt.Errorf("make child mounts private: %w", err)
	}

	// change child root to selected root filesystem
	if err := syscall.Chroot(rootfs); err != nil {
		return fmt.Errorf("change child root to %s: %w", rootfs, err)
	}
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("change working directory to child root: %w", err)
	}
	fmt.Println("child root changed to selected root filesystem")

	// mount child proc filesystem
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		return fmt.Errorf("mount child proc filesystem: %w", err)
	}
	fmt.Println("child proc filesystem mounted at /proc")

	// run the application
	application := exec.Command(arguments[0], arguments[1:]...)
	connectTerminal(application)

	// start the application
	if err := application.Start(); err != nil {
		return fmt.Errorf("start application: %w", err)
	}

	fmt.Println("application PID inside namespace:", application.Process.Pid)
	return application.Wait()
}

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

func connectTerminal(command *exec.Cmd) {
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
}

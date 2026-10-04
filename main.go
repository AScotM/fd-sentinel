package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

type FDTypes struct {
	Files    int
	Sockets  int
	Pipes    int
	Anon     int
	Devices  int
	Other    int
	Unknown  int
}

type ProcessInfo struct {
	PID      int
	UID      uint32
	User     string
	Command  string
	FDs      int
	Types    FDTypes
	Deleted  []DeletedFD
}

type DeletedFD struct {
	PID     int
	FD      int
	User    string
	Command string
	Target  string
	Size    int64
}

type SystemFD struct {
	Allocated uint64
	Unused    uint64
	Maximum   uint64
}

type Config struct {
	Limit       int
	DeletedLimit int
	SortBy      string
	ShowDeleted bool
	All         bool
	MinFDs      int
}

func main() {
	config := parseFlags()

	if _, err := os.Stat("/proc"); err != nil {
		fatal("fd-sentinel requires a Linux /proc filesystem")
	}

	systemFD, err := readSystemFD()
	if err != nil {
		fatal("cannot read system file descriptor statistics: %v", err)
	}

	processes, err := scanProcesses()
	if err != nil {
		fatal("cannot scan /proc: %v", err)
	}

	processes = filterProcesses(processes, config.MinFDs)
	sortProcesses(processes, config.SortBy)

	totalVisibleFDs := 0
	totalDeleted := 0
	totalSockets := 0
	totalPipes := 0
	totalAnon := 0
	totalFiles := 0
	totalDevices := 0
	totalOther := 0
	totalUnknown := 0

	var deleted []DeletedFD

	for _, p := range processes {
		totalVisibleFDs += p.FDs
		totalDeleted += len(p.Deleted)
		totalSockets += p.Types.Sockets
		totalPipes += p.Types.Pipes
		totalAnon += p.Types.Anon
		totalFiles += p.Types.Files
		totalDevices += p.Types.Devices
		totalOther += p.Types.Other
		totalUnknown += p.Types.Unknown
		deleted = append(deleted, p.Deleted...)
	}

	sort.Slice(deleted, func(i, j int) bool {
		if deleted[i].Size == deleted[j].Size {
			if deleted[i].PID == deleted[j].PID {
				return deleted[i].FD < deleted[j].FD
			}
			return deleted[i].PID < deleted[j].PID
		}
		return deleted[i].Size > deleted[j].Size
	})

	printHeader()
	printSystemSummary(
		systemFD,
		len(processes),
		totalVisibleFDs,
		totalDeleted,
		totalFiles,
		totalSockets,
		totalPipes,
		totalAnon,
		totalDevices,
		totalOther,
		totalUnknown,
	)

	printProcesses(processes, config)

	if config.ShowDeleted {
		printDeleted(deleted, config.DeletedLimit, config.All)
	}
}

func parseFlags() Config {
	var config Config

	flag.IntVar(&config.Limit, "limit", 15, "maximum number of processes to display")
	flag.IntVar(&config.DeletedLimit, "deleted-limit", 15, "maximum deleted descriptors to display")
	flag.StringVar(&config.SortBy, "sort", "fds", "sort by fds, sockets, pipes, files, anon, devices, deleted, pid, user, or command")
	flag.BoolVar(&config.ShowDeleted, "deleted", true, "show deleted-but-open descriptors")
	flag.BoolVar(&config.All, "all", false, "show all processes and deleted descriptors")
	flag.IntVar(&config.MinFDs, "min-fds", 0, "only include processes with at least this many descriptors")

	flag.Usage = func() {
		out := flag.CommandLine.Output()

		fmt.Fprintf(out, "fd-sentinel - Linux file descriptor observer\n\n")
		fmt.Fprintf(out, "Usage:\n")
		fmt.Fprintf(out, "  fd-sentinel [options]\n\n")
		fmt.Fprintf(out, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if config.Limit < 1 {
		config.Limit = 1
	}

	if config.DeletedLimit < 1 {
		config.DeletedLimit = 1
	}

	if config.MinFDs < 0 {
		config.MinFDs = 0
	}

	validSorts := map[string]bool{
		"fds":     true,
		"sockets": true,
		"pipes":   true,
		"files":   true,
		"anon":    true,
		"devices": true,
		"deleted": true,
		"pid":     true,
		"user":    true,
		"command": true,
	}

	config.SortBy = strings.ToLower(config.SortBy)

	if !validSorts[config.SortBy] {
		fatal("invalid sort field %q", config.SortBy)
	}

	return config
}

func readSystemFD() (SystemFD, error) {
	data, err := os.ReadFile("/proc/sys/fs/file-nr")
	if err != nil {
		return SystemFD{}, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return SystemFD{}, errors.New("unexpected /proc/sys/fs/file-nr format")
	}

	allocated, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return SystemFD{}, err
	}

	unused, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return SystemFD{}, err
	}

	maximum, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return SystemFD{}, err
	}

	return SystemFD{
		Allocated: allocated,
		Unused:    unused,
		Maximum:   maximum,
	}, nil
}

func scanProcesses() ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	processes := make([]ProcessInfo, 0, 256)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}

		info, err := inspectProcess(pid)
		if err != nil {
			continue
		}

		processes = append(processes, info)
	}

	return processes, nil
}

func inspectProcess(pid int) (ProcessInfo, error) {
	base := filepath.Join("/proc", strconv.Itoa(pid))

	uid, err := processUID(filepath.Join(base, "status"))
	if err != nil {
		return ProcessInfo{}, err
	}

	command := processCommand(base)

	fdDir := filepath.Join(base, "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return ProcessInfo{}, err
	}

	info := ProcessInfo{
		PID:     pid,
		UID:     uid,
		User:    username(uid),
		Command: command,
	}

	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		path := filepath.Join(fdDir, entry.Name())

		target, err := os.Readlink(path)
		if err != nil {
			continue
		}

		info.FDs++

		kind := classifyDescriptor(path, target)

		switch kind {
		case "file":
			info.Types.Files++
		case "socket":
			info.Types.Sockets++
		case "pipe":
			info.Types.Pipes++
		case "anon":
			info.Types.Anon++
		case "device":
			info.Types.Devices++
		case "other":
			info.Types.Other++
		default:
			info.Types.Unknown++
		}

		if isDeletedTarget(target) {
			size := descriptorSize(path)

			info.Deleted = append(info.Deleted, DeletedFD{
				PID:     pid,
				FD:      fd,
				User:    info.User,
				Command: command,
				Target:  target,
				Size:    size,
			})
		}
	}

	return info, nil
}

func processUID(statusPath string) (uint32, error) {
	file, err := os.Open(statusPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, "Uid:") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, errors.New("malformed Uid field")
		}

		value, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return 0, err
		}

		return uint32(value), nil
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return 0, errors.New("Uid field not found")
}

func processCommand(base string) string {
	cmdline, err := os.ReadFile(filepath.Join(base, "cmdline"))
	if err == nil && len(cmdline) > 0 {
		parts := strings.Split(string(cmdline), "\x00")

		if len(parts) > 0 && parts[0] != "" {
			name := filepath.Base(parts[0])

			if name != "" && name != "." && name != "/" {
				return sanitize(name)
			}
		}
	}

	comm, err := os.ReadFile(filepath.Join(base, "comm"))
	if err == nil {
		value := strings.TrimSpace(string(comm))
		if value != "" {
			return sanitize(value)
		}
	}

	return "?"
}

func username(uid uint32) string {
	value := strconv.FormatUint(uint64(uid), 10)

	u, err := user.LookupId(value)
	if err != nil {
		return value
	}

	if u.Username == "" {
		return value
	}

	return u.Username
}

func classifyDescriptor(path, target string) string {
	switch {
	case strings.HasPrefix(target, "socket:["):
		return "socket"
	case strings.HasPrefix(target, "pipe:["):
		return "pipe"
	case strings.HasPrefix(target, "anon_inode:"):
		return "anon"
	}

	var stat syscall.Stat_t

	if err := syscall.Stat(path, &stat); err != nil {
		return "unknown"
	}

	mode := stat.Mode & syscall.S_IFMT

	switch mode {
	case syscall.S_IFREG:
		return "file"
	case syscall.S_IFDIR:
		return "file"
	case syscall.S_IFBLK:
		return "device"
	case syscall.S_IFCHR:
		return "device"
	case syscall.S_IFIFO:
		return "pipe"
	case syscall.S_IFSOCK:
		return "socket"
	case syscall.S_IFLNK:
		return "other"
	default:
		return "other"
	}
}

func isDeletedTarget(target string) bool {
	return strings.HasSuffix(target, " (deleted)")
}

func descriptorSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}

	return info.Size()
}

func filterProcesses(processes []ProcessInfo, minFDs int) []ProcessInfo {
	if minFDs <= 0 {
		return processes
	}

	filtered := make([]ProcessInfo, 0, len(processes))

	for _, process := range processes {
		if process.FDs >= minFDs {
			filtered = append(filtered, process)
		}
	}

	return filtered
}

func sortProcesses(processes []ProcessInfo, field string) {
	sort.SliceStable(processes, func(i, j int) bool {
		a := processes[i]
		b := processes[j]

		switch field {
		case "sockets":
			if a.Types.Sockets != b.Types.Sockets {
				return a.Types.Sockets > b.Types.Sockets
			}
		case "pipes":
			if a.Types.Pipes != b.Types.Pipes {
				return a.Types.Pipes > b.Types.Pipes
			}
		case "files":
			if a.Types.Files != b.Types.Files {
				return a.Types.Files > b.Types.Files
			}
		case "anon":
			if a.Types.Anon != b.Types.Anon {
				return a.Types.Anon > b.Types.Anon
			}
		case "devices":
			if a.Types.Devices != b.Types.Devices {
				return a.Types.Devices > b.Types.Devices
			}
		case "deleted":
			if len(a.Deleted) != len(b.Deleted) {
				return len(a.Deleted) > len(b.Deleted)
			}
		case "pid":
			return a.PID < b.PID
		case "user":
			if a.User != b.User {
				return a.User < b.User
			}
		case "command":
			if a.Command != b.Command {
				return a.Command < b.Command
			}
		default:
			if a.FDs != b.FDs {
				return a.FDs > b.FDs
			}
		}

		if a.FDs != b.FDs {
			return a.FDs > b.FDs
		}

		return a.PID < b.PID
	})
}

func printHeader() {
	fmt.Println()
	fmt.Println("FD SENTINEL")
	fmt.Println(strings.Repeat("=", 72))
	fmt.Printf("Snapshot: %s\n", time.Now().Format("2006-01-02 15:04:05"))
}

func printSystemSummary(
	system SystemFD,
	processes int,
	visibleFDs int,
	deleted int,
	files int,
	sockets int,
	pipes int,
	anon int,
	devices int,
	other int,
	unknown int,
) {
	fmt.Println()
	fmt.Println("SYSTEM")

	inUse := system.Allocated

	if system.Allocated >= system.Unused {
		inUse = system.Allocated - system.Unused
	}

	fmt.Printf("Kernel allocated : %s\n", formatUint(system.Allocated))
	fmt.Printf("Kernel unused    : %s\n", formatUint(system.Unused))
	fmt.Printf("Kernel in use    : %s\n", formatUint(inUse))
	fmt.Printf("Kernel maximum   : %s\n", formatUint(system.Maximum))

	if system.Maximum > 0 {
		percent := float64(inUse) / float64(system.Maximum) * 100
		fmt.Printf("Kernel usage     : %.4f%%\n", percent)
	}

	fmt.Printf("Visible processes: %s\n", formatInt(processes))
	fmt.Printf("Visible FDs      : %s\n", formatInt(visibleFDs))
	fmt.Printf("Deleted open     : %s\n", formatInt(deleted))

	fmt.Println()
	fmt.Println("DESCRIPTOR TYPES")
	fmt.Printf("Files            : %s\n", formatInt(files))
	fmt.Printf("Sockets          : %s\n", formatInt(sockets))
	fmt.Printf("Pipes            : %s\n", formatInt(pipes))
	fmt.Printf("Anonymous        : %s\n", formatInt(anon))
	fmt.Printf("Devices          : %s\n", formatInt(devices))
	fmt.Printf("Other            : %s\n", formatInt(other))
	fmt.Printf("Unknown          : %s\n", formatInt(unknown))
}

func printProcesses(processes []ProcessInfo, config Config) {
	fmt.Println()
	fmt.Println("PROCESS DESCRIPTORS")

	if len(processes) == 0 {
		fmt.Println("No accessible processes found.")
		return
	}

	limit := len(processes)

	if !config.All && config.Limit < limit {
		limit = config.Limit
	}

	writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)

	fmt.Fprintln(
		writer,
		"PID\tUSER\tFDS\tFILES\tSOCKETS\tPIPES\tANON\tDEV\tOTHER\tUNK\tDEL\tCOMMAND",
	)

	for _, p := range processes[:limit] {
		fmt.Fprintf(
			writer,
			"%d\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n",
			p.PID,
			truncate(p.User, 16),
			p.FDs,
			p.Types.Files,
			p.Types.Sockets,
			p.Types.Pipes,
			p.Types.Anon,
			p.Types.Devices,
			p.Types.Other,
			p.Types.Unknown,
			len(p.Deleted),
			truncate(p.Command, 32),
		)
	}

	writer.Flush()

	if limit < len(processes) {
		fmt.Printf(
			"\nShowing %d of %d processes. Use -all or increase -limit.\n",
			limit,
			len(processes),
		)
	}
}

func printDeleted(deleted []DeletedFD, limit int, all bool) {
	fmt.Println()
	fmt.Println("DELETED BUT OPEN")

	if len(deleted) == 0 {
		fmt.Println("None detected.")
		return
	}

	count := len(deleted)

	if !all && limit < count {
		count = limit
	}

	writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)

	fmt.Fprintln(
		writer,
		"PID\tFD\tUSER\tSIZE\tCOMMAND\tTARGET",
	)

	for _, item := range deleted[:count] {
		fmt.Fprintf(
			writer,
			"%d\t%d\t%s\t%s\t%s\t%s\n",
			item.PID,
			item.FD,
			truncate(item.User, 16),
			formatBytes(item.Size),
			truncate(item.Command, 24),
			truncate(item.Target, 64),
		)
	}

	writer.Flush()

	if count < len(deleted) {
		fmt.Printf(
			"\nShowing %d of %d deleted descriptors. Use -all or increase -deleted-limit.\n",
			count,
			len(deleted),
		)
	}
}

func formatBytes(size int64) string {
	if size < 0 {
		return "?"
	}

	const unit = 1024

	if size < unit {
		return fmt.Sprintf("%d B", size)
	}

	div := int64(unit)
	exp := 0

	for n := size / unit; n >= unit && exp < 5; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}

	return fmt.Sprintf("%.1f %s", float64(size)/float64(div), units[exp])
}

func formatInt(value int) string {
	return formatUint(uint64(value))
}

func formatUint(value uint64) string {
	s := strconv.FormatUint(value, 10)

	if len(s) <= 3 {
		return s
	}

	var builder strings.Builder

	first := len(s) % 3
	if first == 0 {
		first = 3
	}

	builder.WriteString(s[:first])

	for i := first; i < len(s); i += 3 {
		builder.WriteByte(',')
		builder.WriteString(s[i : i+3])
	}

	return builder.String()
}

func truncate(value string, width int) string {
	value = sanitize(value)

	if width <= 0 {
		return ""
	}

	runes := []rune(value)

	if len(runes) <= width {
		return value
	}

	if width <= 3 {
		return string(runes[:width])
	}

	return string(runes[:width-3]) + "..."
}

func sanitize(value string) string {
	value = strings.ReplaceAll(value, "\t", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")

	return strings.TrimSpace(value)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "fd-sentinel: "+format+"\n", args...)
	os.Exit(1)
}

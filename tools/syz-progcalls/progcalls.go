package main

import (
	"flag"
	"fmt"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strings"
)

var (
	flagOS         = flag.String("os", runtime.GOOS, "target os")
	flagArch       = flag.String("arch", runtime.GOARCH, "target arch")
	flagProcs      = flag.Int("procs", 1, "number of parallel processes")
	flagSlowdown   = flag.Int("slowdown", 1, "execution slowdown caused by emulation/instrumentation")
	flagSandbox    = flag.String("sandbox", "", "sandbox to use (none, setuid, namespace)")
	flagProgDir    = flag.String("dir", "", "directory of file(s) with programs to read")
	flagFaultCall  = flag.Int("fault_call", -1, "inject fault into this call (0-based)")
	flagFaultNth   = flag.Int("fault_nth", 0, "inject fault on n-th operation (0-based)")
	flagHandleSegv = flag.Bool("segv", false, "catch and ignore SIGSEGV")
	flagRepro      = flag.Bool("repro", false, "add heartbeats used by pkg/repro")
)

func main() {
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
	if *flagProgDir == "" {
		flag.Usage()
		os.Exit(1)
	}
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	files, err := ioutil.ReadDir(*flagProgDir)
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), "syz") {
			data, err := ioutil.ReadFile(*flagProgDir + "/" + f.Name())
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
				os.Exit(1)
			}

			mode := prog.NonStrict
			p, err := target.Deserialize(data, mode)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("File: %s \n", f.Name())
			for _, call := range p.Calls {
				fmt.Printf("Syscall name: %s\n", call.Meta.Name)
				fmt.Printf("Syscall number: %d\n", call.Meta.NR)
				for _, a := range call.Meta.Args {
					fmt.Printf("Syscall arg: %s, type: %s\n", a.Name, a.Type)
				}
				fmt.Printf("\n")
			}
		}
	}

}

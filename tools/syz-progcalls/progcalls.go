package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
)

/*Below 3 structs only used for formatting JSON output */
type BugReproducer struct {
	Filename string `json:"File"`
	Calls    []SysCallDesc
}
type SysCallDesc struct {
	Name      string `json:"SyscallName"`
	NR        uint64 `json:"SyscallNR"`
	Arguments []JsonArgs
}
type JsonArgs struct {
	ArgName string
	ArgType string
	HasVal  bool
	ArgVal  string
}


type OpenFlag int64
const(
	RDONLY OpenFlag = 0
	WRONLY OpenFlag = 1
	RDWR OpenFlag = 2
)

var (
	flagOS         = flag.String("os", runtime.GOOS, "target os")
	flagArch       = flag.String("arch", runtime.GOARCH, "target arch")
	flagProcs      = flag.Int("procs", 1, "number of parallel processes")
	flagSlowdown   = flag.Int("slowdown", 1, "execution slowdown caused by emulation/instrumentation")
	flagSandbox    = flag.String("sandbox", "", "sandbox to use (none, setuid, namespace)")
	flagProgDir    = flag.String("dir", "", "directory of file(s) with programs to read")
	flagProg       = flag.String("p", "", "file with program to read")
	flagFaultCall  = flag.Int("fault_call", -1, "inject fault into this call (0-based)")
	flagFaultNth   = flag.Int("fault_nth", 0, "inject fault on n-th operation (0-based)")
	flagDebug      = flag.Bool("debug", false, "show syscall parsing messages")
	flagRepro      = flag.Bool("repro", false, "add heartbeats used by pkg/repro")
	flagPrintJson  = flag.Bool("print", false, "print JSON output to stdout")
	flagExportJson = flag.String("json", "", "<filename> output syscall descriptions to JSON file")
)

var callsToParse = map[string]bool{
	"open":   true,
	"openat": true,
}

func main() {
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
	if *flagProgDir == "" && *flagProg == "" {
		flag.Usage()
		os.Exit(1)
	}
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	var files = make([]fs.FileInfo, 0)

	if *flagProgDir != "" || *flagProg != "" {
		if *flagProgDir != "" {
			dir, err := ioutil.ReadDir(*flagProgDir)
			if err != nil {
				log.Fatal(err)
			}
			files = append(files, dir...)
		} else {
			f, err := os.Open(*flagProg)
			if err != nil {
				log.Fatal(err)
			}
			s, err := f.Stat()
			if err != nil {
				log.Fatal(err)
			}
			files = append(files, s)
		}

		var reprosJson = make([]BugReproducer, 0)

		for _, f := range files {
			if !f.IsDir() && strings.HasSuffix(f.Name(), "syz") {

				var fp string
				if *flagProgDir != "" {
					fp = *flagProgDir + "/" + f.Name()
				} else {
					fp = f.Name()
				}

				data, err := ioutil.ReadFile(fp)
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

				r := BugReproducer{Filename: f.Name(), Calls: make([]SysCallDesc, 0)}

				if *flagDebug {
					fmt.Printf("File: %s \n", f.Name())
				}

				var parsed = make(map[string]int)
				for key, _ := range callsToParse {
					parsed[key] = 0
				}

				for _, call := range p.Calls {
					if *flagDebug {
						fmt.Printf("Syscall name: %s -- ", call.Meta.Name)
						fmt.Printf("number: %d -- ", call.Meta.NR)
						fmt.Printf("Syscall comment: %s\n", call.Comment)
						fmt.Printf("args(name, type): -- ")
					}

					var simpleCall = SysCallDesc{
						Name:      call.Meta.Name,
						NR:        call.Meta.NR,
						Arguments: make([]JsonArgs, 0),
					}
					var p = ""
					var pf = ""
					var flags = ""
					var valExists = false
					var strippedCall = strings.Split(call.Meta.Name, "$")[0]
					if callsToParse[call.Meta.Name] || callsToParse[strippedCall]{
						p, pf = parseOpenCall(fp, parsed[call.Meta.Name], call.Meta.Name)
						parsed[call.Meta.Name] += 1
					}

					if pf != ""{
						if (hexStringToInt(pf) & RDWR) == RDWR{
							flags = "RDWR"
						}else if (hexStringToInt(pf) & WRONLY) == WRONLY{
							flags = "WRONLY"
						}else{
							flags = "RDONLY"
						}
					}

					if p != "" {
						valExists = true
					}

					for _, a := range call.Meta.Args {
						if *flagDebug {
							fmt.Printf(" %s, %s -", a.Name, a.Type)
						}
						var v = ""
						var b = false
						if a.Name == "file" {
							v = p
							b = valExists
						}
						if a.Name != "" {
							simpleArg := JsonArgs{
								ArgName: a.Name,
								ArgType: a.Type.String(),
								ArgVal:  v,
								HasVal:  b,
							}
							if a.Name == "flags" {
								simpleArg.ArgVal = flags
								simpleArg.HasVal = true
							}
							simpleCall.Arguments = append(simpleCall.Arguments, simpleArg)
						}
					}
					if callsToParse[call.Meta.Name] || callsToParse[strippedCall] {
						r.Calls = append(r.Calls, simpleCall)
					}
					if *flagDebug {
						fmt.Printf("\n")
					}
				}
				reprosJson = append(reprosJson, r)
			}
		}
		if *flagExportJson != "" {
			var jsonFiltered = make([]BugReproducer, 0)
			for _, ent := range reprosJson {
				if len(ent.Calls) > 0 {
					jsonFiltered = append(jsonFiltered, ent)
				}
			}
			writeJson(jsonFiltered)
		}
	}
}
func hexStringToInt(hex string) OpenFlag {
	var x int64
	x, _ = strconv.ParseInt(hex, 16, 64)
	return OpenFlag(x)
}
func writeJson(repros []BugReproducer) {
	jsonOut := struct {
		Repros []BugReproducer `json:"kasan-repros"`
	}{
		repros,
	}

	fmt.Println(len(repros))
	f, _ := json.MarshalIndent(jsonOut, "", " ")
	_ = ioutil.WriteFile(*flagExportJson, f, 0644)
}

func parseOpenCall(fp string, pos int, callName string) (string, string) {
	file, err := os.Open(fp)
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(file)
	var scannedCalls = 0
	var fpStr = ""
	var openFlags = ""
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, callName+"("){
			if scannedCalls == pos {
				var argStr = line[strings.Index(line, callName+"(") : len(line)-1]
				var split = strings.Split(argStr, ",")
				for i, a := range split {
					var e = strings.Index(a, "\\x00")
					var s = strings.Index(a, "='")
					if e != -1 && s != -1 {
						fpStr = a[s+2 : e]
						if i < len(split) - 1 {
							openFlags = strings.Replace(strings.TrimSpace(split[i+1]), "0x", "", -1)
						}
						break
					}
				}
			}
			scannedCalls++
		}
	}
	return fpStr, openFlags
}

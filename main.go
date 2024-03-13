package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"k8s.io/klog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var wg = sync.WaitGroup{}

// var in = "/root/gopath/data/predict_ipv6_asn7922.txt"

var (
	//in           string = "/root/gopath/data/predict_ipv6_asn7922.txt"
	limit        int64  = 50
	process      int64  = 15
	inDirectory  string = "E:\\python_code\\go_scan\\src\\github.com"
	outDirectory string = "E:\\python_code\\go_scan\\src\\github.com"
)

func init() {
	flag.Int64Var(&limit, "limit", int64(limit), "limitation")
	flag.Int64Var(&process, "process", int64(process), "go routine numbers")
	//flag.StringVar(&in, "in", string(in), "input file")
	flag.StringVar(&inDirectory, "in", string(inDirectory), "input file path")
	flag.StringVar(&outDirectory, "out", string(outDirectory), "output file path")
}
func GetFileListByPath(inDirectory string) (err error, fileList []string) {

	files, err := ioutil.ReadDir(inDirectory) //read the files from the inDirectory
	if err != nil {
		fmt.Println("error reading inDirectory:", err) //print error if inDirectory is not read properly
	}
	for _, file := range files {
		fileList = append(fileList, file.Name())
	}
	return
}
func main() {
	flag.Parse()
	err, list := GetFileListByPath(inDirectory)
	if err != nil {
		panic(err)
	}
	for i := range list {

		runLoop(list[i])

	}
	//fmt.Println(list)

}
func runLoop(inFile string) {
	var file string
	if strings.HasSuffix(inFile, "/") {
		file = fmt.Sprintf("%s%s", inDirectory, inFile)
	} else {
		// MEIYOU
		file = fmt.Sprintf("%s/%s", inDirectory, inFile)
	}

	ips, err := readIPS(file)
	if err != nil {
		klog.Error(err)
		//panic(err)
	}
	suffix := time.Now().Format("2006-01-02")
	// todo 改后缀
	fileName := strings.Split(inFile, ".")[0] + "_" + suffix + ".log"
	outSuccFile := outDirectory + "ipv6_succ_" + fileName
	outFailFile := outDirectory + "ipv6_fail_" + fileName

	fileopts := NewFileOperations([]string{outSuccFile, outFailFile})
	defer func() {
		fileopts.showlines(inFile)
		fileopts.closeFile()
	}()
	event := make(chan struct{}, process)
	for _, ip := range ips {
		event <- struct{}{}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			pingV6(ip, fileopts)
			<-event

		}(ip)

	}
	wg.Wait()

}
func readIPS(path string) ([]string, error) {
	fileHanle, err := os.OpenFile(path, os.O_RDONLY, 0666)
	if err != nil {
		panic(err)
	}

	defer fileHanle.Close()

	reader := bufio.NewReader(fileHanle)

	var results = []string{}
	// 按行处理txt
	index := int64(0)
	for {
		if index >= limit {
			fmt.Printf("out of limiation %v\n", limit)
			return results, nil
		}
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		if string(line) == "" {
			continue
		}
		results = append(results, string(line))
		index++
	}

	return results, nil
}

type fileOperations struct {
	sync.Mutex
	line []int64
	file []*os.File
}

func NewFileOperations(path []string) *fileOperations {
	files := make([]*os.File, 0)
	for _, p := range path {
		file, err := os.Create(p)
		if err != nil {
			fmt.Printf("unexpected error %v", err)
			os.Exit(-1)
		}
		files = append(files, file)
	}
	return &fileOperations{
		Mutex: sync.Mutex{},
		file:  files,
		line:  make([]int64, 2),
	}
}
func (f *fileOperations) closeFile() {
	for _, file := range f.file {
		file.Close()
	}
}

func (f *fileOperations) showlines(in string) {
	fmt.Printf("%s successful ips: %v failed ips: %v\n", in, f.line[0], f.line[1])
}

const (
	OPTS_SUC   = "suc"
	OPT_FAILED = "failed"
)

func (f *fileOperations) saveInfos(opts, result string) error {
	f.Mutex.Lock()
	defer f.Mutex.Unlock()
	switch opts {
	case OPTS_SUC:
		f.file[0].WriteString(result)
		f.line[0]++
	case OPT_FAILED:
		f.file[1].WriteString(result)
		f.line[1]++
	default:
		return fmt.Errorf("invalid opts")
	}
	return nil
}

func pingV6(ip string, fileOpts *fileOperations) {
	// fmt.Println(ip)
	command := exec.Command("/bin/bash", "-c", fmt.Sprintf("ping -6 -c 2 -i 0.01 -s 8 -W 1 -w 2 %v | grep ttl | wc -l", ip))
	out, err := command.CombinedOutput()
	if err != nil {
		if msg, ok := err.(*exec.ExitError); ok && msg.ExitCode() != 1 {
			fileOpts.saveInfos(OPT_FAILED, fmt.Sprintf("invalid ip: %v,count %v", ip, string(out)))
			return
		}
	}
	if strings.TrimSpace(string(out)) != "0" {
		fileOpts.saveInfos(OPTS_SUC, fmt.Sprintf("%v,%v", ip, string(out)))
		return
	}
	fileOpts.saveInfos(OPT_FAILED, fmt.Sprintf("%v,%v", ip, string(out)))
}

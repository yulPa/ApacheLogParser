package main

import (
        "github.com/yulPa/ApacheLogParser"
        "flag"
        "fmt"
        "log"
)

func main() {

        log_path := flag.String("log", "", "Log Path")
        flag.Parse()

        stats, err := yulparserApache.ParseLogFile_Get_Stats(*log_path)
        if err != nil {
                log.Fatal(err)
        }

        // print JSON :)
        fmt.Println(string(stats))
}

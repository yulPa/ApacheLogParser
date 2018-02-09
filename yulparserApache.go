package ApacheLogParser

import (
        "bufio"
        "bytes"
        "encoding/json"
        "fmt"
        "log"
        "os"
        "regexp"
        "strconv"
        "strings"
)

// Line : Represents a line in standard Apache log
type Line struct {
        Method  string
        Request string
        Status  string
        Bytes   int
        URL     string
}

func readLines(path string) ([]string, error) {
        file, err := os.Open(path)
        if err != nil {
                return nil, err
        }
        defer file.Close()

        var lines []string
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
                lines = append(lines, scanner.Text())
        }
        return lines, scanner.Err()
}

func ParseLogFile_Get_Stats(file string) ([]byte, error) {

        var AllReq int
        var TotalBytes int

        countHttpCode := make(map[string]int)
        countHttpExt := make(map[string]int)


        lines, err := readLines(file)
        if err != nil {
                log.Fatalf("readLines: %s", err)
        }

        for _, line := range lines {

                var buffer bytes.Buffer

                buffer.WriteString(`"(\S*)\s?`)                 // 1) method
                buffer.WriteString(`(?:((?:[^"]*(?:\\")?)*)\s`) // 2) URL
                buffer.WriteString(`([^"]*)"\s|`)               // 3) protocol
                buffer.WriteString(`((?:[^"]*(?:\\")?)*)"\s)`)  // 4) or, possibly URL with no protocol
                buffer.WriteString(`(\S+)\s`)                   // 5) status code
                buffer.WriteString(`(\S+)\s`)                   // 6) bytes

                re1, err := regexp.Compile(buffer.String())
                if err != nil {
                    log.Fatalf("regexp: %s", err)
                }

                result := re1.FindStringSubmatch(line)

                // we check if we match a result before we process, if error, we go to the next line
                if result == nil {
                    continue
                }

                lineItem := new(Line)

                lineItem.Method = result[1]

                nbr_bytes, err := strconv.Atoi(result[6])
                if err != nil {
                    nbr_bytes = 0
                }

                lineItem.Status = result[5]
                lineItem.Bytes = nbr_bytes
                url := result[2]
                altURL := result[4]
                if url == "" && altURL != "" {
                    url = altURL
                }
                lineItem.URL = strings.ToLower(url)

                counterHttp := fmt.Sprintf("%s_%s", lineItem.Method, lineItem.Status)

                var extRegexp = regexp.MustCompile(`\.([[:alnum:]]{2,5}$)|([[:alnum:]]{2,5})\?`)
                extFName := extRegexp.FindStringSubmatch(lineItem.URL)
                //fmt.Println(len(extFName))
           		// we check if we match a result before we process, if error, we go to the next line
           		validExt := map[string]bool{"jpg": true,"png": true,"gif": true,"css": true,"js": true,"ico": true,"cer":  true,"csr": true,"htm": true,"html": true,"xhtml": true,"rss": true,"xml": true,"csv": true,"dat": true,"pps": true,"pptx": true,"ppt": true,"tar": true,"zip": true,
           		"vcf": true,"doc": true,"docx": true,"log": true,"svg": true,"eot": true,"ttf": true,"woff": true,"sql": true,"txt": true,"xls": true,"xlsx": true,"md": true,"pdf": true,"mp3": true,"wav": true,"wma": true,"avi": true,"flv": true,"m4v": true,"mov": true,"mp4": true,"mpg": true,"swf": true,"wmv": true}
                if len(extFName) != 0 {
                   
				        extName  := strings.Replace(extFName[0],".","",-1)
				    	extName  = strings.Replace(extName,"?","",-1)             

				    	if validExt[extName] {
					 		counterExt := fmt.Sprintf("%s_%s", "EXT", extName)	
					        // counter by extention
							countHttpExt[counterExt]++
						}
                }

				// counter by HTTPCODE and STATUS
				countHttpCode[counterHttp]++		

                // count all hits
                AllReq++

                // Add Total Bytes
                TotalBytes = TotalBytes + lineItem.Bytes


        }

        // merge counter EXT to counter HTTP Code so we can return one json
        for k, v := range countHttpExt {
                countHttpCode[k] = v
        }
        countHttpCode["TotalBytes"] = TotalBytes
        stats, err := json.Marshal(countHttpCode)
        if err != nil {
                panic(err)
        }
        //fmt.Println(string(jsonCounter))

        return stats, nil
}

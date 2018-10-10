package main

import (
    "fmt"
    "time"
    "strings"
    "io/ioutil"
    "net/http"
)

var header = `//go:generate go run internal/cmd/generate_items.go
package kolgo

// Array of all in-game items, generated from src/data/items.txt file
// from the KoLMafia source on %s

type Item struct {
    ID       string
    Name     string
    DescID   string
    Image    string
    Use      string
    Access   string
    Autosell int
    Plural   string
}

var AllItems = []*Item{
%s}
`

func main() {
    r, err := http.Get(`https://raw.githubusercontent.com/mkszuba/kolmafia/master/src/data/items.txt`)
    if err != nil {
        fmt.Println(err)
        r, err = http.Get(`https://sourceforge.net/p/kolmafia/code/HEAD/tree/src/data/items.txt?format=raw`)
    }

    if err != nil {
        panic(err)
    }
    defer r.Body.Close()

    body, _ := ioutil.ReadAll(r.Body)
    lines   := strings.Split(string(body), "\n")
    items := ""
    for _, line := range lines {
        if strings.HasPrefix(line, `#`) {
            continue
        }
        m := strings.Split(line, "\t")
        if len(m) < 5 {
            items = items + "    nil,\n"
        } else {
            b := make([]interface{}, 8)
            for i, x := range m {
                b[i] = x
            }
            if b[7] == nil {
                b[7] = interface{}("")
            }

            items = items + fmt.Sprintf(`    &Item{"%s", "%s", "%s", "%s", "%s", "%s", %s, "%s"},`, b...) + "\n"
        }
    }

    fmt.Printf(header, time.Now().Format(time.RFC850), items)
}


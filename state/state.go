package state

import (
	"log"
	"os"
)

var Channel chan string = make(chan string, 1000)

func SaveLog() {
	f, err := os.OpenFile("audit.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
		f.Close()
		return
	}
	defer f.Close()
	for {
		msg, ok := <-Channel
		if !ok {
			break
		}
		log.Println(msg)
		f.WriteString(msg + "\n")
	}
}

package main

import (
	"log"
	"os/exec"
	"time"

	"github.com/fsnotify/fsnotify"
)

func (app *App) watchFileZone() {
	watcher, err := fsnotify.NewWatcher()
	watcher.Add(app.ZoneFilePath)
	if err != nil {
		log.Fatal(err)
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				log.Println("watcher channel returned false")
				return
			}
			log.Println("event:", event)
			if event.Has(fsnotify.Write) {
				log.Println("zone file has been modified")
				if err := app.RecordCache.refresh(app.ZoneFilePath); err != nil {
					log.Printf("Failed to refresh records: %s", err)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("error:", err)
		}
	}

}

func (app *App) runSyncCommand() {
	defer func() { <-app.syncCh }() // release the lock when done

	cmd := exec.Command("rndc", "sync")
	err := cmd.Run()
	if err != nil {
		log.Printf("Failed to execute sync command: %s", err)
		return
	}
	log.Println("Successfully executed rndc sync")
	time.Sleep(time.Second)
	if err := app.RecordCache.refresh(app.ZoneFilePath); err != nil {
		log.Printf("Failed to refresh records: %s", err)
	}
	log.Println("Successfully refreshed records")
}

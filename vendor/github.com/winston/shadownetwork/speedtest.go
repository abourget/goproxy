package shadownetwork

import (
	"fmt"
	//"github.com/jonnrb/speedtest"
	//"context"
	//"log"
	//"github.com/jonnrb/speedtest/geo"
	"time"
	"os"
	//"io/ioutil"
	//"encoding/gob"
	"bytes"
	"os/exec"
	"strings"
	//"bufio"
	"regexp"
	"strconv"
	client "github.com/influxdata/influxdb/client/v2"
	"encoding/json"
)

const (
	bandwidthRefreshDays	= 5			// Measure the local bandwidth every X days
	cfgTime			= 10			// Timeout for getting initial configuration
	pngTime  		= 10 			// Timeout for latency detection phase
	ulTime			= 20			// Timeout for upload test
	dlTime			= 10			// Timeout for download test
)

type BandwidthMeasurement struct {
	Upload    int64
	Download  int64
	LastCheck time.Time
}

func queryDB(clnt client.Client, cmd string, databasename string) (res []client.Result, err error) {
	q := client.Query{
		Command:  cmd,
		Database: databasename,
	}
	if response, err := clnt.Query(q); err == nil {
		if response.Error() != nil {
			return res, response.Error()
		}
		res = response.Results
	} else {
		return res, err
	}
	return res, nil
}

// Returns the local bandwidth measurement from speedtest-cli
// Force is used to run a bandwidth test even if we have a recent result
// TODO: Loop every 24 hours and retest in case device stays on for that long.
func MeasureBandwidth(force bool, sn *ShadowNetwork, speedtestclient string, databasename string) (int64, int64) {

	// Ensure that speedtest-cli exists. Panic if it doesn't because lack of bandwidth measurements can dramatically slow down the network.
	_, err := os.Stat(speedtestclient)
	//if err != nil && os.IsNotExist(err) {
	//	fmt.Printf("[WARN] Invalid location for speedtest client. This file must exist. [%s]\n", speedtestclient)
	//}

	var c client.Client
	if databasename != "" {
		var err error
		conf := client.HTTPConfig{
			Addr:	"http://127.0.0.1:8086",
		}
		c, err = client.NewHTTPClient(conf)
		if err != nil {
			fmt.Printf("[ERROR] Couldn't start InfluxDB Client. Can't save bandwidth. err=%v\n", err)

			// We'll still run the bandwidth test but won't try to read or write the results
			databasename = ""
		}
	}
	defer c.Close()

	//fmt.Printf("  Checking for prior measurement: %s\n", filename)

	// We only force a measurement during unit testing so clear out the prior results.
	if force {
		fmt.Println("[INFO] Dropping old bandwidth measurements.")
		q := fmt.Sprintf("drop measurement bandwidth")
		queryDB(c, q, databasename)
	}

	var avgdownload, avgupload, nummeasurements int64
	if databasename != "" {
		q:= fmt.Sprintf("SELECT time, mean(download), mean(upload), count(*) from bandwidth")
		res, err := queryDB(c, q, databasename)
		if err == nil {
			if len(res) > 0 && len(res[0].Series) > 0 {
				for _, row := range res[0].Series[0].Values {
					//if err == nil {
						// Can't use direct conversion because influxdb might store bandwidth as decimal.
						// Strip off decimal point and anything to the right so we can convert to int64.
						val := string(row[1].(json.Number))
						decind := strings.LastIndex(val, ".")
						if decind > 0 {
							val = val[:decind]
						}
						avgdownload, err = strconv.ParseInt(val, 10, 64)

						val = string(row[2].(json.Number))
						decind = strings.LastIndex(val, ".")
						if decind > 0 {
							val = val[:decind]
						}
						avgupload, _ = strconv.ParseInt(val, 10, 64)

						val = string(row[3].(json.Number))
						decind = strings.LastIndex(val, ".")
						if decind > 0 {
							val = val[:decind]
						}
						nummeasurements, _ = strconv.ParseInt(val, 10, 64)
					//}
					//fmt.Printf("[DEBUG] Bandwidth:\n %+v \n download: %d\n upload: %d\n num measurements: %d\n err:%+v\n", res[0].Series[0].Values, avgdownload, avgupload, nummeasurements, err)

					// Save the existing measurements to the shadownetwork object. They will act as a placeholder
					// if we have to retake them.
					if sn != nil {
						sn.Download = avgdownload
						sn.Upload = avgupload
					}

					//bandwidthdownloadMBps := float64(avgdownload) / 1024.0 / 1024.0
					//bandwidthuploadMBps := float64(avgupload) / 1024.0 / 1024.0
					//fmt.Printf("[INFO] Average bandwidth from %d prior measurements: Download=%v bytes/sec [%5.1f MB/sec ] Upload=%v [%5.1f MB/sec ]\n", nummeasurements, avgdownload, bandwidthdownloadMBps, avgupload, bandwidthuploadMBps)

					if !force {
						// Check last update time to see if we need to run a new one
						q := fmt.Sprintf("select last(upload) from bandwidth")
						res, err := queryDB(c, q, databasename)
						if err == nil {
							if len(res) > 0 && len(res[0].Series) > 0 {
								row := res[0].Series[0].Values[0]
								lastcheck, err := time.Parse(time.RFC3339, (row[0]).(string))
								//fmt.Printf("[DEBUG] time check", lastcheck, time.Now().Local().Add(bandwidthRefreshDays * -24 * time.Hour))
								if err == nil {
									//if lastcheck.After(time.Now().Local().Add(bandwidthRefreshDays * -23 * time.Hour)) {
										if lastcheck.After(time.Now().Local().Add(-4 * time.Hour)) {
										//fmt.Printf("[INFO] Skipping bandwidth check because was run less than 4 hours ago\n")
										return avgdownload, avgupload
									}
								}
							}
						} else {
							fmt.Printf("[ERROR] Error while checking last bandwidth update time.\n")
						}
					} else {
						fmt.Printf("[INFO] Forcing new bandwidth measurement\n")
					}
				}
			}

		}
	}

	// Embedded speed test was giving readings only 20% of max. Switch to command line version to ensure
	// it isn't competing for resources with the current process.

	// Important: github.com/surol/speedtest-cli must be installed in current directory

	// If we don't have a bandwidth measurement, use a temporary placeholder. This should be overwritten by the actual
	// measurement which follows.
	if sn != nil && sn.Upload == 0 {
		fmt.Println("[WARN] No bandwidth measurement available. Using temporary default of 1 Mib/sec.")
		// 1 Mib/sec is the default
		sn.Upload = 1024 * 1024 / 8
	}

	// Results are in Mib/s, which is 1024^2/8 bytes per second
	fmt.Printf("[INFO] Running new bandwidth measurement [%s]\n", speedtestclient)


	cmd := exec.Command(speedtestclient)
	cmdOutput := &bytes.Buffer{}
	cmd.Stdout = cmdOutput
	err = cmd.Run()
	if err != nil {
		//fmt.Printf("  *** Error probing download speed: %v\n", err)
		return 0, 0
	}

	// Default values
	output := string(cmdOutput.Bytes())
	//fmt.Printf("  Command output: %s\n", output)

	d, u := ParseSpeedtestOutput(output)

	//fmt.Println(d, u)
	newdownload := int64(d * 1024 * 1024)	// bytes/sec
	newupload := int64(u * 1024 * 1024)	// bytes/sec

	//fmt.Println("[DEBUG] measurements", newdownload, newupload)

	// Calculates average from new and old bandwidth measurements
	// If we don't have a prior measurement, then just use this one.
	avgdownload = (newdownload + avgdownload * nummeasurements) / (nummeasurements + 1)
	avgupload = (newupload + avgupload * nummeasurements) / (nummeasurements + 1)

	if sn != nil {
		// save bandwidth measurements in shadownetwork object
		sn.Download = avgdownload
		sn.Upload = avgupload
	}

	// Save results to influxDB
	SaveBandwidth(databasename, newupload, newdownload)

	// The function always returns this particular measurement, not a rolling average
	return avgdownload, avgupload

}

func SaveBandwidth(database string, upload int64, download int64) {
	if database != "" {
		var c client.Client
		var err error
		conf := client.HTTPConfig{
			Addr:	"http://127.0.0.1:8086",
		}
		c, err = client.NewHTTPClient(conf)
		defer c.Close()
		if err != nil {
			fmt.Printf("[ERROR] Couldn't start InfluxDB Client. Can't save bandwidth. err=%v\n", err)
			return
		}


		fmt.Printf("[INFO] Saving new bandwidth results to disk\n")
		bp, err := client.NewBatchPoints(client.BatchPointsConfig{
			Database:  database,
			Precision: "us",
		})

		if err != nil {
			fmt.Printf("[ERROR] Couldn't create InfluxDB BatchPoints object. %+v\n", err)
		} else {

			// Create a point and add to batch
			tags := map[string]string{"category": "local"}
			fields := map[string]interface{}{
				"download":   download,
				"upload": upload,
			}

			pt, err := client.NewPoint("bandwidth", tags, fields, time.Now().Local())
			if err != nil {
				fmt.Printf("[ERROR] Couldn't save bandwidth data point to InfluxDB %+v\n", err)
			} else {
				bp.AddPoint(pt)

				// Write the batch
				if err := c.Write(bp); err != nil {
					fmt.Printf("[ERROR] Couldn't persist bandwidth results to InfluxDB %+v\n", err)
				}
			}
		}

		// Close client
		c.Close()
	} else {
		fmt.Printf("[WARN] Couldn't save bandwidth measurement. No database provided.\n")
	}
}
func ParseSpeedtestOutput(output string) (float64, float64) {
	//scanner := bufio.NewScanner(strings.NewReader(output))
	reDownload := regexp.MustCompile(`Download:\s([\d\.]*)\sMib`)
	reUpload := regexp.MustCompile(`Upload:\s([\d\.]*)\sMib`)

	download := 0.0
	upload := 0.0

	d := reDownload.FindString(output)
	if len(d) > 0 {
		d = strings.Replace(d, "Download: ", "", 1)
		d = strings.Replace(d, " Mib", "", 1)
		download, _ = strconv.ParseFloat(d, 64)
		//fmt.Printf("  ParseFloat:", download)
	}

	u := reUpload.FindString(output)
	if len(d) > 0 {
		u = strings.Replace(u, "Upload: ", "", 1)
		u = strings.Replace(u, " Mib", "", 1)
		upload, _ = strconv.ParseFloat(u, 64)
		//fmt.Printf("  ParseFloat:", upload)
	}

	return download, upload

}


/*
func listServers(ctx context.Context, client *speedtest.Client) []speedtest.Server {
	servers, err := client.LoadAllServers(ctx)
	if err != nil {
		log.Fatalf("Failed to load server list: %v\n", err)
	}
	if len(servers) == 0 {
		log.Fatalf("No servers found somehow...")
	}
	return servers
}

func selectServer(client *speedtest.Client, cfg speedtest.Config, servers []speedtest.Server) speedtest.Server {
	var (
		distance geo.Kilometers
		latency  time.Duration
		server   speedtest.Server
	)

	ctx, cancel := context.WithTimeout(context.Background(), pngTime * time.Second)
	defer cancel()

	// Manual server selection - we're fully automatic for now
	*/
/*if *srvID != 0 {
		id := speedtest.ServerID(*srvID)

		// Meh, linear search.
		i := -1
		for j, s := range servers {
			if s.ID == id {
				i = j
				break
			}
		}
		if i == -1 {
			log.Fatalf("Server not found: %d\n", id)
		}

		server = servers[i]
		l, err := server.AverageLatency(ctx, client, speedtest.DefaultLatencySamples)
		if err != nil {
			log.Fatalf("Error getting latency for (%v): %v", server, err)
		}

		latency = l
		distance = cfg.Coordinates.DistanceTo(server.Coordinates)
	} else {*//*

		distanceMap := speedtest.SortServersByDistance(servers, cfg.Coordinates)

		// Truncate to just a few of the closest servers for the latency test.
		const maxCloseServers = 5
		closestServers := func() []speedtest.Server {
			if len(servers) > maxCloseServers {
				return servers[:maxCloseServers]
			} else {
				return servers
			}
		}()

		latencyMap, err := speedtest.StableSortServersByAverageLatency(
			closestServers, ctx, client, speedtest.DefaultLatencySamples)
		if err != nil {
			log.Fatalf("Error getting server latencies: %v", err)
		}

		server = closestServers[0]
		latency = latencyMap[server.ID]
		distance = distanceMap[server.ID]
	//}

	fmt.Printf("Using server hosted by %s (%s) [%v]: %.1f ms\n",
		server.Sponsor, server.Name, distance, float64(latency)/float64(time.Millisecond))

	return server
}

*/

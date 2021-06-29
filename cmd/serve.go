/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	_ "bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"gopkg.in/square/go-jose.v2"
	"io"
	"net/http"
	"os"
	"time"
)

var (
	port    int
	keyfile string
)

// serveCmd represents the serve command
var servCmd = &cobra.Command{
	Use:   "serve",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: startServer,
}

func startServer(cmd *cobra.Command, args []string) {
	router := mux.NewRouter()
	router.HandleFunc("/ping", PingHandler).Methods(http.MethodPost)

	serv := &http.Server{
		Handler:      router,
		Addr:         fmt.Sprintf(":%d", port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  10 * time.Second,
	}

	log.Info().Int("Port", port).Str("Keyfile", keyfile).Msg("Server Started")
	serv.ListenAndServe()
}
func init() {
	servCmd.Flags().IntVar(&port, "port", 8080, "Port for server to listen on")
	servCmd.Flags().StringVar(&keyfile, "key", "client.key", "File for JWE private key")
	rootCmd.AddCommand(servCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
func PingHandler(w http.ResponseWriter, r *http.Request) {
	type payload struct {
		Msg   string `json:"msg"`
		Nonce string `json:"nonce"`
	}

	pl := payload{}
	if encdata, err := io.ReadAll(r.Body); err == nil {
		
		
		examineData(encdata)

		if data, err := decrypt_data(encdata, keyfile); err == nil {
			log.Info().Str("Unencrypted Data", string(data)).Send()
			if err := json.Unmarshal(data, &pl); err == nil {
				//This is kind of a big deal. I could have just changed the msg string from 'ping' to 'pong' but then
				//Any other crappy data supplied would have been carried along. I could be even more aggressive, making
				//a map[string][string] and disallowed any unknown keys. I still might.
				if pl.Msg == "ping" {
					respMsg := payload{
						Msg:   "pong",
						Nonce: pl.Nonce,
					}
					w.WriteHeader(http.StatusOK)
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(respMsg)
				} else {
					w.WriteHeader(http.StatusNotAcceptable)
					log.Error().Msg("Wrong Message Sent")
				}
			} else {
				w.WriteHeader(http.StatusNotAcceptable)
				log.Err(err).Send()
			}
		} else {
			log.Err(err).Msg("Could not decrypt data")
			w.WriteHeader(http.StatusNotAcceptable)
		}
	} else {
		w.WriteHeader(http.StatusNotAcceptable)
		log.Err(err).Send()
	}

}

func decrypt_data(data []byte, keyFile string) ([]byte, error) {
	if key_data, err := os.ReadFile(keyFile); err == nil {
		block, rest := pem.Decode(key_data)
		if block != nil {
			if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if object, err := jose.ParseEncrypted(string(data)); err == nil {
					if decrypted, err := object.Decrypt(key); err == nil {
						log.Info().Str("Message", string(decrypted)).Msg("message unencrypted")
						return decrypted, nil
					} else {
						log.Err(err).Msg("cannot decrypt")
					}
				} else {
					log.Err(err).Msg("cannot parse encrypted data")
				}
			} else {
				log.Err(err).Msg("can't parse private key")
			}
		} else {
			log.Err(fmt.Errorf("Failed")).Str("Rest", string(rest)).Msg("could not parse key_data for a block")
		}
	} else {
		log.Err(fmt.Errorf("cannot read file")).Msg("cannot read file")
	}

	return nil, fmt.Errorf("Failed")
}
func examineData(data []byte){
	info := map[string]interface{}{}
	log.Info().Msg("Examining Data...")

	if err := json.Unmarshal(data, &info);err == nil{
		log.Info().Msgf("%#v", info)
	} else {
		log.Error().Msgf("Could Not Unmarshal Data")
	}

	log.Info().Msg("End examining Data...")
}

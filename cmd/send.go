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
	_ "fmt"

	"bytes"
	"crypto/x509"
	_ "encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"gopkg.in/square/go-jose.v2"
	"io"
	"net/http"
	"os"
	"time"
)

var (
	data     string
	certFile string
	destURL  string
)

// sendCmd represents the send command
var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send encrypted data to a server",
	Long: ` Provide an x509 certificate, a server url and data. Send will encrypt the data into a
	JWE object using the public key of the certificate and send it to the provided server.  `,
	Run: func(cmd *cobra.Command, args []string) {
		//fmt.Println("send called")
		log.Info().Str("data", data).
			Str("Certificate", certFile).
			Str("Destination", destURL).Send()
		if key, err := getPublicKey(certFile); err == nil {
			log.Info().Msg("key retrieved")
			if encData, err := encrypt(key, []byte(data)); err == nil {
				if resp, err := SendData(encData, destURL); err == nil {
					log.Info().Str("Response", resp.Status).Send()
					if data, err := io.ReadAll(resp.Body); err == nil {
						log.Info().Str("Body", string(data)).Send()
					} else {
						log.Error().Msg("Could not read response body")
					}
				} else {
					log.Err(err).Send()
				}
			} else {
				log.Err(err).Send()
			}
		} else {
			log.Err(err).Send()
		}
	},
}

func init() {
	sendCmd.Flags().StringVar(&data, "data", "", "Data to send to the server")
	sendCmd.Flags().StringVar(&certFile, "cert", "client_cert.crt", "Certificate file")
	sendCmd.Flags().StringVar(&destURL, "dest", "http://localhost:8080/data", "Destination URL")
	sendCmd.MarkFlagRequired("data")
	rootCmd.AddCommand(sendCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// sendCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// sendCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
func getPublicKey(fileName string) (interface{}, error) {
	if cert_data, err := os.ReadFile(fileName); err == nil {

		block, rest := pem.Decode(cert_data)

		if block != nil {

			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				log.Info().Int("Version", cert.Version).Str("Public Key Algorithm", cert.PublicKeyAlgorithm.String()).
					Str("Key Type", fmt.Sprintf("%T", cert.PublicKey)).Send()
				return cert.PublicKey, nil
			} else {
				log.Err(err).Send()
			}
		} else {
			log.Err(fmt.Errorf("could not parse certificate block", string(rest)))
		}

		return nil, fmt.Errorf("Could not generate Public Key")
	} else {
		return nil, err
	}
}
func encrypt(key interface{}, data []byte) ([]byte, error) {
	//lets add some EncrypterOptions
	eo := &jose.EncrypterOptions{}

	// Instantiate an encrypter using RSA-OAEP with AES128-GCM. An error would
	// indicate that the selected algorithm(s) are not currently supported.
	publicKey := key
	if encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.RSA_OAEP, Key: publicKey}, eo); err == nil {

		// Encrypt a sample plaintext. Calling the encrypter returns an encrypted
		// JWE object, which can then be serialized for output afterwards. An error
		// would indicate a problem in an underlying cryptographic primitive.
		//var plaintext = []byte("Lorem ipsum dolor sit amet")
		if object, err := encrypter.Encrypt(data); err == nil {

			// Serialize the encrypted object using the full serialization format.
			// Alternatively you can also use the compact format here by calling
			// object.CompactSerialize() instead.
			serialized := object.FullSerialize()
			return []byte(serialized), nil
		} else {
			log.Err(err).Send()
			return []byte{}, err
		}
	} else {
		log.Err(err).Send()
		return []byte{}, err
	}
}
func SendData(data []byte, url string) (*http.Response, error) {
	log.Info().Str("Message", string(data)).Msg("Sending Data")
	if duration, err := time.ParseDuration("5s"); err == nil {
		client := &http.Client{
			Timeout: duration,
		}
		if req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data)); err == nil {
			log.Info().Msg("Request Ready")
			if resp, err := client.Do(req); err == nil {
				log.Info().Msg("Data Sent")
				return resp, err
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
	} else {
		return nil, err
	}
}

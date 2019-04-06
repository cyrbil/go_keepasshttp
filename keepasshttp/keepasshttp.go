// Package keepasshttp provide tools to see and manipulate KeePass credentials through keePassHTTP plugin.
package keepasshttp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

const defaultServerUrl = "http://localhost:19455/"
const defaultStorageName = ".go_keepass_http"

// Credential is a container for KeePass credential.
type Credential struct {
	Login        string
	Password     string
	Url          string
	Uuid         string
	StringFields map[string]string

	kph *keePassHTTP
}

// Commit update an existing entry in KeePass database.
// It won't work on a newly created Credential, use use `kph.update(credential)` instead.
func (credential *Credential) Commit() error {
	if credential.kph == nil {
		return fmt.Errorf(
			"credential is not bound to a keePassHTTP instance, use `kph.update(credential)` instead")
	}
	return credential.kph.Update(credential)
}

// Filter is a group of string used for filtering KeePass entries.
// All fields are optional.
type Filter struct {
	Url       string
	SubmitUrl string
	Realm     string
}

// keePassHTTP is a class to manipulate KeePass credentials using keePassHTTP protocol.
type keePassHTTP struct {
	// Url is the listening keePassHTTP's server address.
	Url string
	// Storage is the file path to store private association key (default to "~/.python_keepass_http").
	Storage string

	uid    string
	key    []byte
	dbHash string

	httpClient httpClient
	randBytes  func(int) ([]byte, error)
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// New creates a keePassHTTP instance with default values
func New() *keePassHTTP {
	kph := new(keePassHTTP)

	// replace mock fields
	kph.httpClient = &http.Client{Timeout: time.Second * 30}
	kph.randBytes = new(aes256CBCPksc7).randBytes

	return kph
}

// List all entries that look like an url.
// Passwords are omitted.
func (kph *keePassHTTP) List() (credentials []*Credential, err error) {
	defer kph.catchError(&err)
	result := kph.request(&body{
		RequestType: "get-all-logins",
	})
	if result != nil {
		kph.getCredentials(result, &credentials)
	}
	return
}

// Count entries for a given `Filter`.
// Filtering is done the same as `Search` method.
func (kph *keePassHTTP) Count(filter *Filter) (credentialsCount int, err error) {
	defer kph.catchError(&err)
	result := kph.request(&body{
		RequestType: "get-logins-count",
		Url:         filter.Url,
		SubmitUrl:   filter.SubmitUrl,
		Realm:       filter.Realm,
	})

	if result != nil {
		credentialsCount = result.Count
	}
	return
}

// Search all matching entries for a given `Filter`.
// For every entry, the Levenshtein Distance of his Entry-URL (or Title, if Entry-URL is not set)
// to the `Url` is calculated.
// Only the entries with the minimal distance are returned.
func (kph *keePassHTTP) Search(filter *Filter) (credentials []*Credential, err error) {
	defer kph.catchError(&err)
	result := kph.request(&body{
		RequestType: "get-logins",
		Url:         filter.Url,
		SubmitUrl:   filter.SubmitUrl,
		Realm:       filter.Realm,
	})
	if result != nil {
		kph.getCredentials(result, &credentials)
	}
	return
}

// Get a single matching entry for a given `Filter`.
// For every entry, the Levenshtein Distance of his Entry-URL (or Title, if Entry-URL is not set)
// to the ``key`` is calculated.
// Only the entry with the minimal distance is returned
func (kph *keePassHTTP) Get(filter *Filter) (credential *Credential, err error) {
	credentials, err := kph.Search(filter)
	if credentials != nil && len(credentials) > 0 {
		credential = credentials[0]
	}
	return
}

// Create a new credential into KeePass
func (kph *keePassHTTP) Create(credential *Credential) (err error) {
	defer kph.catchError(&err)
	kph.request(&body{
		RequestType: "set-login",
		Url:         credential.Url,
		Login:       credential.Login,
		Password:    credential.Password,
		// create can also use `Realm` and `SubmitUrl`
		// but it's an useless and undocumented feature
	})
	return
}

// Update a credential into KeePass.
// KeePass will prompt for validation only when a change is detected.
func (kph *keePassHTTP) Update(credential *Credential) (err error) {
	if credential.Uuid == "" {
		return fmt.Errorf("cannot update a credential without its uuid")
	}
	defer kph.catchError(&err)
	kph.request(&body{
		RequestType: "set-login",
		Uuid:        credential.Uuid,
		Url:         credential.Url,
		Login:       credential.Login,
		Password:    credential.Password,
	})
	return
}

func (kph *keePassHTTP) getCredentials(result *body, credentials *[]*Credential) {
	for _, entry := range result.Entries {
		credential := new(Credential)
		credential.Uuid = entry.Uuid
		credential.Url = entry.Url
		credential.Login = entry.Login
		credential.Password = entry.Password
		credential.StringFields = make(map[string]string, len(entry.StringFields))
		for _, field := range entry.StringFields {
			credential.StringFields[field.Key] = field.Value
		}
		credential.kph = kph
		*credentials = append(*credentials, credential)
	}
}

// panicOrPass is just a dumb way to get 100% coverage
// some region were impossible to check for errors
// this act as a general try catch
func (kph *keePassHTTP) panicOrPass(err error) {
	if err != nil {
		panic(err)
	}
}

func (kph *keePassHTTP) catchError(err *error) {
	if r := recover(); r != nil {
		*err = r.(error)
	}
}

func (kph *keePassHTTP) setDefaults() {
	if kph.Storage == "" {
		usr, err := user.Current()
		kph.panicOrPass(err)
		kph.Storage = filepath.Join(usr.HomeDir, defaultStorageName)
	}
	if kph.Url == "" {
		kph.Url = defaultServerUrl
	}
}

func (kph *keePassHTTP) load() {
	kph.setDefaults()

	if _, err := os.Stat(kph.Storage); os.IsNotExist(err) {
		kph.key, err = kph.randBytes(32)
		kph.panicOrPass(err)

		kph.uid, kph.dbHash = kph.register()

		fd, err := os.OpenFile(kph.Storage, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		kph.panicOrPass(err)
		defer fd.Close()

		data := []string{
			base64.StdEncoding.EncodeToString([]byte(kph.uid)),
			base64.StdEncoding.EncodeToString([]byte(kph.key)),
			base64.StdEncoding.EncodeToString([]byte(kph.dbHash)),
		}
		toWrite := strings.Join(data, "\n")
		_, err = fd.WriteString(toWrite)
		kph.panicOrPass(err)
	} else {
		fd, err := os.OpenFile(kph.Storage, os.O_RDONLY, 0600)
		kph.panicOrPass(err)
		defer fd.Close()

		data, err := ioutil.ReadAll(fd)
		kph.panicOrPass(err)
		content := string(data)

		parts := strings.Split(content, "\n")
		if len(parts) != 3 {
			err := fmt.Errorf("invalid number of lines in storage %#v", kph.Storage)
			kph.panicOrPass(err)
		}

		tmp, err := base64.StdEncoding.DecodeString(parts[0])
		kph.panicOrPass(err)
		kph.uid = string(tmp)
		tmp, err = base64.StdEncoding.DecodeString(parts[1])
		kph.panicOrPass(err)
		kph.key = tmp
		tmp, err = base64.StdEncoding.DecodeString(parts[2])
		kph.panicOrPass(err)
		kph.dbHash = string(tmp)
	}

	kph.authenticate()
}

func (kph *keePassHTTP) register() (uid string, dbHash string) {
	data := kph.request(&body{
		RequestType: "associate",
		Key:         base64.StdEncoding.EncodeToString(kph.key),
	})
	kph.registerValidate(data)
	return data.Id, data.Hash
}

func (kph *keePassHTTP) registerValidate(data *body) {
	if data.Id == "" {
		err := fmt.Errorf("fail to associate with keePassHTTP, no app id returned")
		kph.panicOrPass(err)
	}
	if data.Hash == "" {
		err := fmt.Errorf("fail to associate with keePassHTTP, no app database hash returned")
		kph.panicOrPass(err)
	}
}

func (kph *keePassHTTP) authenticate() {
	defer func() {
		if r := recover(); r != nil {
			panic(fmt.Errorf(
				"fail to authenticate to KeePassHTTP. Possible errors are:\n"+
					" - Wrong database is opened\n"+
					" - Wrong key exchange storage (current: %#v)\n"+
					"(detail: %#v)",
				kph.Storage, r,
			))
		}
	}()
	kph.request(&body{
		RequestType:   "test-associate",
		TriggerUnlock: true,
	})
}

func (kph *keePassHTTP) request(requestData *body) (responseData *body) {
	if kph.key == nil {
		kph.load()
	}

	jsonRequestData := kph.requestPrepare(requestData)
	responseData = kph.requestSend(jsonRequestData)
	kph.responseValidate(responseData)
	return
}

func (kph *keePassHTTP) requestPrepare(requestData *body) (jsonRequestData []byte) {
	aes, err := NewAES256CBCPksc7(kph.key, nil)
	kph.panicOrPass(err)
	iv := base64.StdEncoding.EncodeToString(aes.iv)

	requestData.Id = kph.uid
	requestData.Nonce = iv
	requestData.Verifier = iv

	err = kph.encryptBody(aes, requestData)
	kph.panicOrPass(err)

	jsonRequestData, err = json.MarshalIndent(requestData, "", "    ")
	kph.panicOrPass(err)
	return
}

func (kph *keePassHTTP) requestSend(jsonRequestData []byte) (responseData *body) {
	httpRequest, err := http.NewRequest("POST", kph.Url, bytes.NewBuffer(jsonRequestData))
	kph.panicOrPass(err)
	httpRequest.Header.Set("Content-Type", "application/json; charset=utf-8")

	response, err := kph.httpClient.Do(httpRequest)
	kph.panicOrPass(err)
	defer response.Body.Close()

	responseText, err := ioutil.ReadAll(response.Body)
	kph.panicOrPass(err)

	if response.StatusCode != 200 {
		err = fmt.Errorf("keePassHTTP returned an error (detail: %#v)", responseText)
		kph.panicOrPass(err)
	}

	err = json.Unmarshal(responseText, &responseData)
	kph.panicOrPass(err)
	return
}

func (kph *keePassHTTP) responseValidate(responseData *body) {
	if !responseData.Success {
		err := fmt.Errorf("keePassHTTP returned an error (detail: %#v)", responseData.Error)
		kph.panicOrPass(err)
	}

	if responseData.Nonce == "" {
		err := fmt.Errorf("keePassHTTP does not have returned a Nonce")
		kph.panicOrPass(err)
	}
	responseIv, err := base64.StdEncoding.DecodeString(responseData.Nonce)
	kph.panicOrPass(err)

	if responseData.Verifier == "" {
		err = fmt.Errorf("keePassHTTP does not have returned a Verifier")
		kph.panicOrPass(err)
	}
	responseVerifier, err := base64.StdEncoding.DecodeString(responseData.Verifier)
	kph.panicOrPass(err)

	aes, err := NewAES256CBCPksc7(kph.key, responseIv)
	kph.panicOrPass(err)
	signatureIv, err := aes.decrypt(responseVerifier)
	kph.panicOrPass(err)

	/** to debug signature
	goal, _ := aes.encrypt([]byte(responseData.Nonce))
	debug := base64.StdEncoding.EncodeToString(goal)
	fmt.Printf("%#v", debug)
	**/

	if responseData.Nonce != string(signatureIv) {
		err = fmt.Errorf("keePassHTTP invalid signature")
		kph.panicOrPass(err)
	}

	if responseData.Id == "" {
		err = fmt.Errorf("keePassHTTP does not have returned an appId")
		kph.panicOrPass(err)
	}
	if kph.uid != "" && kph.uid != responseData.Id {
		err = fmt.Errorf("keePassHTTP application id mismatch")
		kph.panicOrPass(err)
	}

	if responseData.Hash == "" {
		err = fmt.Errorf("keePassHTTP does not have returned a Hash")
		kph.panicOrPass(err)
	}
	if kph.dbHash != "" && kph.dbHash != responseData.Hash {
		err = fmt.Errorf("keePassHTTP database id mismatch")
		kph.panicOrPass(err)
	}

	err = kph.decryptBody(aes, responseData)
	kph.panicOrPass(err)
}

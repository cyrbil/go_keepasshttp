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

	// for mock testing
	randBytes         func(int) ([]byte, error)
	mockErrorExpected string
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
	result, err := kph.request(&body{
		RequestType: "get-all-logins",
	})
	if err == nil {
		kph.getCredentials(result, &credentials)
	}
	return
}

// Count entries for a given `Filter`.
// Filtering is done the same as `Search` method.
func (kph *keePassHTTP) Count(filter *Filter) (credentialsCount int, err error) {
	result, err := kph.request(&body{
		RequestType: "get-logins-count",
		Url:         filter.Url,
		SubmitUrl:   filter.SubmitUrl,
		Realm:       filter.Realm,
	})

	if err == nil && result != nil {
		credentialsCount = result.Count
	}
	return
}

// Search all matching entries for a given `Filter`.
// For every entry, the Levenshtein Distance of his Entry-URL (or Title, if Entry-URL is not set)
// to the `Url` is calculated.
// Only the entries with the minimal distance are returned.
func (kph *keePassHTTP) Search(filter *Filter) (credentials []*Credential, err error) {
	result, err := kph.request(&body{
		RequestType: "get-logins",
		Url:         filter.Url,
		SubmitUrl:   filter.SubmitUrl,
		Realm:       filter.Realm,
	})
	if err == nil {
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
	if err == nil && len(credentials) > 0 {
		credential = credentials[0]
	}
	return
}

// Create a new credential into KeePass
func (kph *keePassHTTP) Create(credential *Credential) (err error) {
	_, err = kph.request(&body{
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
	_, err = kph.request(&body{
		RequestType: "set-login",
		Uuid:        credential.Uuid,
		Url:         credential.Url,
		Login:       credential.Login,
		Password:    credential.Password,
	})
	return
}

func (kph *keePassHTTP) mockError(currentError string, err *error) (raiseError bool) {
	// used for mocking error that are difficult to trigger or test
	// it always returns false unless a specific error is manually set to be raised
	if currentError != kph.mockErrorExpected {
		return false
	}
	*err = fmt.Errorf("mocked error: %s", currentError)
	return true
}

func (kph *keePassHTTP) getCredentials(result *body, credentials *[]*Credential) {
	if result == nil {
		return
	}
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

func (kph *keePassHTTP) setDefaults() (err error) {
	if kph.Storage == "" {
		var usr *user.User
		usr, err = user.Current()
		if err != nil || kph.mockError("user.Current", &err) {
			return
		}
		kph.Storage = filepath.Join(usr.HomeDir, defaultStorageName)
	}
	if kph.Url == "" {
		kph.Url = defaultServerUrl
	}
	return
}

func (kph *keePassHTTP) loadCreate() (err error) {
	kph.key, err = kph.randBytes(32)
	if err != nil {
		return
	}

	kph.uid, kph.dbHash, err = kph.register()
	if err != nil {
		return
	}

	var fd *os.File
	fd, err = os.OpenFile(kph.Storage, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil || kph.mockError("os.OpenFile", &err) {
		return
	}
	defer fd.Close()

	data := []string{
		base64.StdEncoding.EncodeToString([]byte(kph.uid)),
		base64.StdEncoding.EncodeToString([]byte(kph.key)),
		base64.StdEncoding.EncodeToString([]byte(kph.dbHash)),
	}
	toWrite := strings.Join(data, "\n")
	_, err = fd.WriteString(toWrite)
	kph.mockError("fd.WriteString", &err)
	return
}

func (kph *keePassHTTP) loadOpen() (err error) {
	var fd *os.File
	fd, err = os.OpenFile(kph.Storage, os.O_RDONLY, 0600)
	if err != nil || kph.mockError("os.OpenFile", &err) {
		return
	}
	defer fd.Close()

	var data []byte
	data, err = ioutil.ReadAll(fd)
	if err != nil || kph.mockError("ioutil.ReadAll", &err) {
		return
	}
	content := string(data)

	parts := strings.Split(content, "\n")
	if len(parts) != 3 {
		return fmt.Errorf("invalid number of lines in storage %#v", kph.Storage)
	}

	data, err = base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return
	}
	kph.uid = string(data)

	data, err = base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}
	kph.key = data

	data, err = base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return
	}
	kph.dbHash = string(data)
	return
}

func (kph *keePassHTTP) load() (err error) {
	err = kph.setDefaults()
	if err != nil {
		return
	}

	_, err = os.Stat(kph.Storage)
	if os.IsNotExist(err) {
		err = kph.loadCreate()
		if err != nil {
			return
		}
	} else {
		err = kph.loadOpen()
		if err != nil {
			return
		}
	}

	err = kph.authenticate()
	return err
}

func (kph *keePassHTTP) register() (uid string, dbHash string, err error) {
	data, err := kph.request(&body{
		RequestType: "associate",
		Key:         base64.StdEncoding.EncodeToString(kph.key),
	})
	if err != nil {
		return
	}
	err = kph.registerValidate(data)
	if err != nil || kph.mockError("kph.registerValidate", &err) {
		return
	}
	uid = data.Id
	dbHash = data.Hash
	return
}

func (kph *keePassHTTP) registerValidate(data *body) (err error) {
	if data.Id == "" {
		err = fmt.Errorf("fail to associate with keePassHTTP, no app id returned")
	} else if data.Hash == "" {
		err = fmt.Errorf("fail to associate with keePassHTTP, no app database hash returned")
	}
	return
}

func (kph *keePassHTTP) authenticate() (err error) {
	_, err = kph.request(&body{
		RequestType:   "test-associate",
		TriggerUnlock: true,
	})
	if err != nil {
		err = fmt.Errorf(
			"fail to authenticate to KeePassHTTP. Possible errors are:\n"+
				" - Wrong database is opened\n"+
				" - Wrong key exchange storage (current: %#v)\n"+
				"(detail: %#v)",
			kph.Storage, err,
		)
	}
	return
}

func (kph *keePassHTTP) request(requestData *body) (responseData *body, err error) {
	if kph.key == nil {
		err = kph.load()
		if err != nil {
			return
		}
	}

	jsonRequestData, err := kph.requestPrepare(requestData)
	if err != nil {
		return
	}
	responseData, err = kph.requestSend(jsonRequestData)
	if err != nil {
		return
	}
	err = kph.responseValidate(responseData)
	return
}

func (kph *keePassHTTP) requestPrepare(requestData *body) (jsonRequestData []byte, err error) {
	aes, err := NewAES256CBCPksc7(kph.key, nil)
	if err != nil {
		return
	}
	iv := base64.StdEncoding.EncodeToString(aes.iv)

	requestData.Id = kph.uid
	requestData.Nonce = iv
	requestData.Verifier = iv

	err = kph.encryptBody(aes, requestData)
	if err != nil || kph.mockError("kph.encryptBody", &err) {
		return
	}

	jsonRequestData, err = json.MarshalIndent(requestData, "", "    ")
	return
}

func (kph *keePassHTTP) requestSend(jsonRequestData []byte) (responseData *body, err error) {
	httpRequest, err := http.NewRequest("POST", kph.Url, bytes.NewBuffer(jsonRequestData))
	if err != nil || kph.mockError("http.NewRequest", &err) {
		return
	}
	httpRequest.Header.Set("Content-Type", "application/json; charset=utf-8")

	response, err := kph.httpClient.Do(httpRequest)
	if err != nil || kph.mockError("kph.httpClient.Do", &err) {
		return
	}
	defer response.Body.Close()

	responseText, err := ioutil.ReadAll(response.Body)
	if err != nil || kph.mockError("ioutil.ReadAll", &err) {
		return
	}

	if response.StatusCode != 200 {
		err = fmt.Errorf("keePassHTTP returned an error (detail: %#v)", responseText)
		return
	}

	err = json.Unmarshal(responseText, &responseData)
	return
}

func (kph *keePassHTTP) responseValidate(responseData *body) (err error) {
	if !responseData.Success {
		return fmt.Errorf("keePassHTTP returned an error (detail: %#v)", responseData.Error)
	}

	if responseData.Nonce == "" {
		return fmt.Errorf("keePassHTTP does not have returned a Nonce")
	}
	responseIv, err := base64.StdEncoding.DecodeString(responseData.Nonce)
	if err != nil {
		return
	}

	if responseData.Verifier == "" {
		return fmt.Errorf("keePassHTTP does not have returned a Verifier")
	}
	responseVerifier, err := base64.StdEncoding.DecodeString(responseData.Verifier)
	if err != nil {
		return
	}

	aes, err := NewAES256CBCPksc7(kph.key, responseIv)
	if err != nil {
		return
	}
	signatureIv, err := aes.decrypt(responseVerifier)
	if err != nil {
		return
	}

	/** to debug signature
	goal, _ := aes.encrypt([]byte(responseData.Nonce))
	debug := base64.StdEncoding.EncodeToString(goal)
	fmt.Printf("%#v", debug)
	**/

	if responseData.Nonce != string(signatureIv) {
		return fmt.Errorf("keePassHTTP invalid signature")
	}

	if responseData.Id == "" {
		return fmt.Errorf("keePassHTTP does not have returned an appId")
	}
	if kph.uid != "" && kph.uid != responseData.Id {
		return fmt.Errorf("keePassHTTP application id mismatch")
	}

	if responseData.Hash == "" {
		return fmt.Errorf("keePassHTTP does not have returned a Hash")
	}
	if kph.dbHash != "" && kph.dbHash != responseData.Hash {
		return fmt.Errorf("keePassHTTP database id mismatch")
	}

	err = kph.decryptBody(aes, responseData)
	return
}

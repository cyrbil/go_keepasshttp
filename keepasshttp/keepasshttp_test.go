package keepasshttp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func newKeePassHTTP() *keePassHTTP {
	storage := filepath.Join("..", "tests", "test_storage")
	serverUrl := ""

	fd, err := os.OpenFile(storage, os.O_RDONLY, 0600)
	if err != nil {
		curdir, _ := os.Getwd()
		panic(fmt.Errorf(
			"cannot find storage file %s, be sure to run tests inside project root directory "+
				"(Current folder: %s)",
			storage, curdir))
	}
	fd.Close()

	kph := New()
	kph.Storage = storage
	kph.Url = serverUrl

	_, useRealKeePass := os.LookupEnv("TEST_WITH_KEEPASS")
	if !useRealKeePass {
		// use mock server
		kph.httpClient = new(httpClientMock)
	}

	return kph
}

type httpData struct {
	Input  string
	Output string
	Status int
}
type httpClientMock struct {
	data map[string]*httpData
}

func (c *httpClientMock) Do(req *http.Request) (*http.Response, error) {
	if c.data == nil {
		mockDataFile := filepath.Join("..", "tests", "mock_http.json")
		mockData, _ := ioutil.ReadFile(mockDataFile)
		json.Unmarshal(mockData, &c.data)
	}
	reqBody, _ := req.GetBody()
	reqContent, _ := ioutil.ReadAll(reqBody)
	var reqJson body
	json.Unmarshal(reqContent, &reqJson)

	key := reqJson.RequestType
	if reqJson.Key != "" {
		key += "_Key"
	}

	mock := c.data[key]
	res := &http.Response{
		StatusCode: mock.Status,
		Body:       ioutil.NopCloser(bytes.NewBuffer([]byte(mock.Output))),
	}
	return res, nil
}

/*
func TestKeePassHTTP_catchError(t *testing.T) {
	tests := []struct {
		name    string
		self    *keePassHTTP
		wantErr bool
	}{
		{
			name:    "should be able to catch panic",
			self:    newKeePassHTTP(),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			panicker := func() (err error) {
				defer tt.self.catchError(&err)
				panic(fmt.Errorf("controlled panic"))
			}
			if err := panicker(); (err != nil) != tt.wantErr {
				t.Errorf("keePassHTTP.catchError() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
//*/
func TestKeePassHTTP_List(t *testing.T) {
	tests := []struct {
		name            string
		self            *keePassHTTP
		wantCredentials []string
		wantErr         bool
	}{
		{
			name:            "should list entries of test database",
			self:            newKeePassHTTP(),
			wantCredentials: []string{"861BD08DED5C154C99AEBAFEBA48F739"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCredentials, err := tt.self.List()
			if (err != nil) != tt.wantErr {
				t.Errorf("keePassHTTP.List() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			var gotCredentialsUUID []string
			for _, cred := range gotCredentials {
				gotCredentialsUUID = append(gotCredentialsUUID, cred.Uuid)
			}
			if !reflect.DeepEqual(gotCredentialsUUID, tt.wantCredentials) {
				t.Errorf("keePassHTTP.List() = %v, want %v", gotCredentials, tt.wantCredentials)
			}
		})
	}
}

func TestKeePassHTTP_Count(t *testing.T) {
	type args struct {
		filter *Filter
	}
	tests := []struct {
		name                 string
		self                 *keePassHTTP
		args                 args
		wantCredentialsCount int
		wantErr              bool
	}{
		{
			name:                 "should count entries of test database",
			self:                 newKeePassHTTP(),
			args:                 args{&Filter{Url: "test"}},
			wantCredentialsCount: 4,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCredentialsCount, err := tt.self.Count(tt.args.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("keePassHTTP.Count() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotCredentialsCount != tt.wantCredentialsCount {
				t.Errorf("keePassHTTP.Count() = %v, want %v", gotCredentialsCount, tt.wantCredentialsCount)
			}
		})
	}
}

func TestKeePassHTTP_Search(t *testing.T) {
	type args struct {
		filter *Filter
	}
	tests := []struct {
		name            string
		self            *keePassHTTP
		args            args
		wantCredentials []string
		wantErr         bool
	}{
		{
			name:            "should list entries of test database",
			self:            newKeePassHTTP(),
			args:            args{&Filter{Url: "test"}},
			wantCredentials: []string{"1C23268FFA3AA847972641922BA3F611"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCredentials, err := tt.self.Search(tt.args.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("keePassHTTP.Search() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			var gotCredentialsUUID []string
			for _, cred := range gotCredentials {
				gotCredentialsUUID = append(gotCredentialsUUID, cred.Uuid)
			}
			if !reflect.DeepEqual(gotCredentialsUUID, tt.wantCredentials) {
				t.Errorf("keePassHTTP.Search() = %v, want %v", gotCredentials, tt.wantCredentials)
			}
		})
	}
}

func TestKeePassHTTP_Get(t *testing.T) {
	type args struct {
		filter *Filter
	}
	tests := []struct {
		name           string
		self           *keePassHTTP
		args           args
		wantCredential string
		wantErr        bool
	}{
		{
			name:           "should list entries of test database",
			self:           newKeePassHTTP(),
			args:           args{&Filter{Url: "test"}},
			wantCredential: "1C23268FFA3AA847972641922BA3F611",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCredential, err := tt.self.Get(tt.args.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("keePassHTTP.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotCredential == nil || gotCredential.Uuid != tt.wantCredential {
				t.Errorf("keePassHTTP.Get() = %v, want %v", gotCredential, tt.wantCredential)
			}
		})
	}
}

func TestCredential_Commit(t *testing.T) {
	tests := []struct {
		name       string
		credential *Credential
		wantErr    bool
	}{
		{
			name: "should successfully save credential",
			credential: &Credential{
				Url:      "test",
				Login:    "test",
				Password: "test",
				Uuid:     "1C23268FFA3AA847972641922BA3F611",
				kph:      newKeePassHTTP(),
			},
		},
		{
			name:       "should raise an error when credential is not bound to a kph instance",
			credential: &Credential{kph: nil},
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.credential.Commit(); (err != nil) != tt.wantErr {
				t.Errorf("Credential.Commit() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeePassHTTP_Create(t *testing.T) {
	type args struct {
		credential *Credential
	}
	tests := []struct {
		name    string
		self    *keePassHTTP
		args    args
		wantErr bool
	}{
		{
			name: "should create entry in test database",
			self: newKeePassHTTP(),
			args: args{&Credential{
				Url:      "create",
				Login:    "create",
				Password: "test",
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.self.Create(tt.args.credential); (err != nil) != tt.wantErr {
				t.Errorf("keePassHTTP.Create() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeePassHTTP_Update(t *testing.T) {
	type args struct {
		credential *Credential
	}
	tests := []struct {
		name    string
		self    *keePassHTTP
		args    args
		wantErr bool
	}{
		{
			name: "should update entry in test database",
			self: newKeePassHTTP(),
			args: args{&Credential{
				Url:      "test",
				Login:    "test",
				Password: "test",
				Uuid:     "1C23268FFA3AA847972641922BA3F611",
			}},
		},
		{
			name: "should raise an error when no uuid is provided",
			self: newKeePassHTTP(),
			args: args{&Credential{
				Url:      "test",
				Login:    "test",
				Password: "test",
			}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.self.Update(tt.args.credential); (err != nil) != tt.wantErr {
				t.Errorf("keePassHTTP.Update() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeePassHTTP_load(t *testing.T) {
	tests := []struct {
		name          string
		self          *keePassHTTP
		freshStorage  bool
		keepRandBytes bool
		corruptLine   int
		wantErr       bool
	}{
		{
			name:         "should succeed at creating a new storage",
			self:         newKeePassHTTP(),
			freshStorage: true,
		},
		{
			name:        "should fail with corrupt storage file",
			self:        newKeePassHTTP(),
			corruptLine: -1, // will create empty storage
			wantErr:     true,
		},
		{
			name:        "should fail with corrupt storage file uid",
			self:        newKeePassHTTP(),
			corruptLine: 1,
			wantErr:     true,
		},
		{
			name:        "should fail with corrupt storage file key",
			self:        newKeePassHTTP(),
			corruptLine: 2,
			wantErr:     true,
		},
		{
			name:        "should fail with corrupt storage file hash",
			self:        newKeePassHTTP(),
			corruptLine: 3,
			wantErr:     true,
		},
		{
			name: "should fail when setDefaults fails",
			self: &keePassHTTP{
				httpClient:        new(httpClientMock),
				mockErrorExpected: "user.Current",
			},
			wantErr: true,
		},
		{
			name: "should fail when randBytes fails",
			self: &keePassHTTP{
				httpClient:        new(httpClientMock),
				mockErrorExpected: "kph.randBytes",
				randBytes: func(i int) ([]byte, error) {
					return nil, fmt.Errorf("mocked error: randBytes")
				},
			},
			wantErr:       true,
			keepRandBytes: true,
			freshStorage:  true,
		},
		{
			name: "should fail when kph.register fails",
			self: &keePassHTTP{
				httpClient: new(httpClientMock),
				randBytes:  new(aes256CBCPksc7).randBytes,
			},
			wantErr:       true,
			keepRandBytes: true,
			freshStorage:  true,
		},
		{
			name: "should fail when kph.registerValidate fails",
			self: &keePassHTTP{
				httpClient:        new(httpClientMock),
				mockErrorExpected: "kph.registerValidate",
			},
			wantErr:      true,
			freshStorage: true,
		},
		{
			name: "should fail when os.OpenFile(create) fails",
			self: &keePassHTTP{
				httpClient:        new(httpClientMock),
				mockErrorExpected: "os.OpenFile",
			},
			wantErr:      true,
			freshStorage: true,
		},
		{
			name: "should fail when os.OpenFile(read) fails",
			self: &keePassHTTP{
				httpClient:        new(httpClientMock),
				randBytes:         new(aes256CBCPksc7).randBytes,
				mockErrorExpected: "os.OpenFile",
			},
			wantErr:     true,
			corruptLine: -1,
		},
		{
			name: "should fail when ioutil.ReadAll fails",
			self: &keePassHTTP{
				httpClient:        new(httpClientMock),
				randBytes:         new(aes256CBCPksc7).randBytes,
				mockErrorExpected: "ioutil.ReadAll",
			},
			wantErr:     true,
			corruptLine: -1,
		},
		{
			name: "should fail when fd.WriteString fails",
			self: &keePassHTTP{
				httpClient:        new(httpClientMock),
				randBytes:         new(aes256CBCPksc7).randBytes,
				mockErrorExpected: "fd.WriteString",
			},
			wantErr:      true,
			freshStorage: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.freshStorage {
				tmpFile, err := ioutil.TempFile(os.TempDir(), "keepasshttp_test_storage_")
				if err != nil {
					t.Errorf("test has fail when creating resources (error: %s)", err)
				}
				tmpFile.Close()
				syscall.Unlink(tmpFile.Name())
				tt.self.Storage = tmpFile.Name()
				if !tt.keepRandBytes {
					tt.self.randBytes = func(_ int) ([]byte, error) {
						return base64.StdEncoding.DecodeString("DEBUG+256+bits++++srKysrREVCVUcrMjU2K2JpdHM=")
					}
				}
			}
			if tt.corruptLine != 0 {
				tmpfile, err := ioutil.TempFile(os.TempDir(), "keepasshttp_test_corrupt_storage_")
				if err != nil {
					t.Errorf("test has fail when creating resources (error: %s)", err)
				}
				if tt.corruptLine > 0 {
					storage, err := ioutil.ReadFile(tt.self.Storage)
					if err != nil {
						t.Errorf("test has fail when reading resources (error: %s)", err)
					}
					lines := bytes.Split(storage, []byte("\n"))
					lines[tt.corruptLine-1] = []byte("Corrupt line")
					storage = bytes.Join(lines, []byte("\n"))
					_, err = tmpfile.Write(storage)
					if err != nil {
						t.Errorf("test has fail when writing resources (error: %s)", err)
					}
				}
				tt.self.Storage = tmpfile.Name()
			}
			err := tt.self.load()
			if (err != nil) != tt.wantErr {
				t.Errorf("keePassHTTP.load() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeePassHTTP_setDefaults(t *testing.T) {
	tests := []struct {
		name    string
		self    *keePassHTTP
		wantErr bool
	}{
		{
			name: "should set default when nothing is present",
			self: &keePassHTTP{httpClient: new(httpClientMock)},
		},
		{
			name: "should raise an error when no user if found",
			self: &keePassHTTP{
				httpClient:        new(httpClientMock),
				mockErrorExpected: "user.Current",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.self.setDefaults()
			if (err != nil) != tt.wantErr {
				t.Errorf("keePassHTTP.setDefaults() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeePassHTTP_requestSend(t *testing.T) {
	type args struct {
		jsonRequestData []byte
	}
	tests := []struct {
		name    string
		self    *keePassHTTP
		args    args
		wantErr bool
	}{
		{
			name:    "should raise an error when server answer with non 200",
			self:    &keePassHTTP{httpClient: new(httpClientMock), Url: defaultServerUrl},
			args:    args{[]byte(`{"RequestType": "associate"}`)},
			wantErr: true,
		},
		{
			name: "should raise an error when http.NewRequest fails",
			self: &keePassHTTP{
				httpClient:        new(httpClientMock),
				Url:               defaultServerUrl,
				mockErrorExpected: "http.NewRequest",
			},
			args:    args{[]byte(`{"RequestType": "associate"}`)},
			wantErr: true,
		},
		{
			name: "should raise an error when kph.httpClient.Do fails",
			self: &keePassHTTP{
				httpClient:        new(httpClientMock),
				Url:               defaultServerUrl,
				mockErrorExpected: "kph.httpClient.Do",
			},
			args:    args{[]byte(`{"RequestType": "associate"}`)},
			wantErr: true,
		},
		{
			name: "should raise an error when ioutil.ReadAll fails",
			self: &keePassHTTP{
				httpClient:        new(httpClientMock),
				Url:               defaultServerUrl,
				mockErrorExpected: "ioutil.ReadAll",
			},
			args:    args{[]byte(`{"RequestType": "associate"}`)},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.self.requestSend(tt.args.jsonRequestData)
			if (err != nil) != tt.wantErr {
				t.Errorf("keePassHTTP.requestSend() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeePassHTTP_registerValidate(t *testing.T) {
	type args struct {
		data *body
	}
	tests := []struct {
		name    string
		self    *keePassHTTP
		args    args
		wantErr bool
	}{
		{
			name: "should be ok when appId and dbHash are present",
			self: newKeePassHTTP(),
			args: args{data: &body{Id: "appId", Hash: "dbHash"}},
		},
		{
			name:    "should return an error when no appId was returned",
			self:    newKeePassHTTP(),
			args:    args{data: &body{Hash: "dbHash"}},
			wantErr: true,
		},
		{
			name:    "should return an error when no dbHash was returned",
			self:    newKeePassHTTP(),
			args:    args{data: &body{Id: "appId"}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.self.registerValidate(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("keePassHTTP.registerValidate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeePassHTTP_responseValidate(t *testing.T) {
	type args struct {
		responseData *body
	}
	tests := []struct {
		name    string
		self    *keePassHTTP
		args    args
		wantErr bool
	}{
		{
			name: "should raise an error on unsuccessful response",
			args: args{&body{
				Success: false,
			}},
			wantErr: true,
		},
		{
			name: "should raise an error when no nonce received",
			args: args{&body{
				Success: true,
			}},
			wantErr: true,
		},
		{
			name: "should raise an error when nonce is non base64",
			args: args{&body{
				Success: true,
				Nonce:   "Bad Nonce",
			}},
			wantErr: true,
		},
		{
			name: "should raise an error when nonce is incorrect data",
			args: args{&body{
				Success:  true,
				Nonce:    base64.StdEncoding.EncodeToString([]byte("Invalid")),
				Verifier: "FQAIEowqEkrl/fJTJEL3WjPiby8KC0vC0dniRPY1yc8=",
			}},
			wantErr: true,
		},
		{
			name: "should raise an error when no verifier received",
			args: args{&body{
				Success: true,
				Nonce:   "DEBUG+16+CtERUJVRysxNg==",
			}},
			wantErr: true,
		},
		{
			name: "should raise an error when verifier is non base64",
			args: args{&body{
				Success:  true,
				Nonce:    "DEBUG+16+CtERUJVRysxNg==",
				Verifier: "Bad verifier",
			}},
			wantErr: true,
		},
		{
			name: "should raise an error when aes fails to decrypt",
			args: args{&body{
				Success:  true,
				Nonce:    "DEBUG+16+CtERUJVRysxNg==",
				Verifier: base64.StdEncoding.EncodeToString([]byte("verifier")),
			}},
			wantErr: true,
		},
		{
			name: "should raise an error when signature mismatch nonce",
			args: args{&body{
				Success:  true,
				Nonce:    "DEBUG+16+CtERUJVRysxNg==",
				Verifier: "4ABe1Q7PvTY1kSPgPkeRaw==",
			}},
			wantErr: true,
		},
		{
			name: "should raise an error when no appId received",
			args: args{&body{
				Success:  true,
				Nonce:    "DEBUG+16+CtERUJVRysxNg==",
				Verifier: "FQAIEowqEkrl/fJTJEL3WjPiby8KC0vC0dniRPY1yc8=",
			}},
			wantErr: true,
		},
		{
			name: "should raise an error when appId mismatch",
			args: args{&body{
				Success:  true,
				Nonce:    "DEBUG+16+CtERUJVRysxNg==",
				Verifier: "FQAIEowqEkrl/fJTJEL3WjPiby8KC0vC0dniRPY1yc8=",
				Id:       "invalid debugAppId",
			}},
			wantErr: true,
		},
		{
			name: "should raise an error no dbHash received",
			args: args{&body{
				Success:  true,
				Nonce:    "DEBUG+16+CtERUJVRysxNg==",
				Verifier: "FQAIEowqEkrl/fJTJEL3WjPiby8KC0vC0dniRPY1yc8=",
				Id:       "debugAppId",
			}},
			wantErr: true,
		},
		{
			name: "should raise an error dbHash mismatch",
			args: args{&body{
				Success:  true,
				Nonce:    "DEBUG+16+CtERUJVRysxNg==",
				Verifier: "FQAIEowqEkrl/fJTJEL3WjPiby8KC0vC0dniRPY1yc8=",
				Id:       "debugAppId",
				Hash:     "invalid debugDbHash",
			}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kph := newKeePassHTTP()
			kph.key, _ = base64.StdEncoding.DecodeString("DEBUG+256+bits++++srKysrREVCVUcrMjU2K2JpdHM=")
			kph.uid = "debugAppId"
			kph.dbHash = "debugDbHash"

			err := kph.responseValidate(tt.args.responseData)
			if (err != nil) != tt.wantErr {
				t.Errorf("keePassHTTP.responseValidate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeePassHTTP_authenticate(t *testing.T) {
	tests := []struct {
		name    string
		self    *keePassHTTP
		key     []byte
		wantErr bool
	}{
		{
			name:    "should raise an error on unsuccessful response",
			self:    newKeePassHTTP(),
			key:     []byte("Invalid key"),
			wantErr: true,
		},
		{
			name: "should raise an error on unsuccessful load",
			self: &keePassHTTP{
				mockErrorExpected: "user.Current",
			},
			wantErr: true,
		},
		{
			name: "should raise an error on unsuccessful http request",
			self: &keePassHTTP{
				httpClient:        &httpClientMock{},
				randBytes:         new(aes256CBCPksc7).randBytes,
				mockErrorExpected: "http.NewRequest",
			},
			wantErr: true,
		},
		{
			name: "should raise an error on body encrypt failure",
			self: &keePassHTTP{
				httpClient:        &httpClientMock{},
				randBytes:         new(aes256CBCPksc7).randBytes,
				mockErrorExpected: "kph.encryptBody",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.key != nil {
				tt.self.key = tt.key
			}
			err := tt.self.authenticate()
			if (err != nil) != tt.wantErr {
				t.Errorf("keePassHTTP.authenticate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeePassHTTP_getCredentials(t *testing.T) {
	type args struct {
		result      *body
		credentials *[]*Credential
	}
	tests := []struct {
		name    string
		self    *keePassHTTP
		args    args
		wantErr bool
	}{
		{
			name:    "should accept nil body",
			self:    newKeePassHTTP(),
			args:    args{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.self.getCredentials(tt.args.result, tt.args.credentials)
		})
	}
}

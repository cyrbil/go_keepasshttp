package keepasshttp

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func TestKeePassHTTP_encryptBody(t *testing.T) {
	tests := []struct {
		name              string
		aes               *aes256CBCPksc7
		data              *body
		wantEncryptedData *body
		wantErr           bool
	}{
		{
			name: "should encrypt embedded structures fields",
			aes: &aes256CBCPksc7{
				key: TestKey,
				iv:  TestIv,
			},
			data: &body{
				Entries: []*bodyEntry{{
					StringFields: []*bodyEntryStringField{
						{Key: "EncryptMe!", Value: "EncryptMe!"},
					},
				}},
			},
			wantEncryptedData: &body{
				Entries: []*bodyEntry{{
					StringFields: []*bodyEntryStringField{
						{Key: "SowcQdR+AaeJJp27fDhSZw==", Value: "SowcQdR+AaeJJp27fDhSZw=="},
					},
				}},
			},
		},
		{
			name: "should return an error on encryption failure",
			aes: &aes256CBCPksc7{
				key: []byte("BadKey"),
				iv:  TestIv,
			},
			data: &body{
				Entries: []*bodyEntry{{
					StringFields: []*bodyEntryStringField{
						{Key: "EncryptMe!", Value: "EncryptMe!"},
					},
				}},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			self := new(keePassHTTP)
			err := self.encryptBody(tt.aes, tt.data)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("keePassHTTP.encryptBody() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if !reflect.DeepEqual(tt.data, tt.wantEncryptedData) {
				t.Errorf("keePassHTTP.encryptBody() = %v, want %v", tt.data, tt.wantEncryptedData)
			}
		})
	}
}

func TestKeePassHTTP_decryptBody(t *testing.T) {
	tests := []struct {
		name              string
		aes               *aes256CBCPksc7
		data              *body
		wantEncryptedData *body
		wantErr           bool
	}{
		{
			name: "should decrypt embedded structures fields",
			aes: &aes256CBCPksc7{
				key: TestKey,
				iv:  TestIv,
			},
			data: &body{
				Entries: []*bodyEntry{{
					StringFields: []*bodyEntryStringField{
						{Key: "DaJaS+X4z5h4NHW1axzqIQ==", Value: "DaJaS+X4z5h4NHW1axzqIQ=="},
					},
				}},
			},
			wantEncryptedData: &body{
				Entries: []*bodyEntry{{
					StringFields: []*bodyEntryStringField{
						{Key: "DecryptMe!", Value: "DecryptMe!"},
					},
				}},
			},
		},
		{
			name: "should fails for incorrect base64 string",
			aes: &aes256CBCPksc7{
				key: TestKey,
				iv:  TestIv,
			},
			data: &body{
				Url: "incorrect base64",
			},
			wantErr: true,
		},
		{
			name: "should fails for incorrect aes string",
			aes: &aes256CBCPksc7{
				key: TestKey,
				iv:  TestIv,
			},
			data: &body{
				Url: base64.StdEncoding.EncodeToString([]byte("incorrect aes")),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			self := new(keePassHTTP)
			err := self.decryptBody(tt.aes, tt.data)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("keePassHTTP.decryptBody() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if !reflect.DeepEqual(tt.data, tt.wantEncryptedData) {
				t.Errorf("keePassHTTP.decryptBody() = %v, want %v", tt.data, tt.wantEncryptedData)
			}
		})
	}
}

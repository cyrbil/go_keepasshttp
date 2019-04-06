# Go KeePassHTTP

[![version.svg][version.svg]][version.url]
[![godoc.svg][godoc.svg]][godoc.url]
[![report.svg][report.svg]][report.url]
[![stability.svg][stability.svg]][stability.url]
 
[![license.svg][license.svg]][license.url]
[![travis_build.svg][travis_build.svg]][travis.url]
[![codecov.svg][codecov.svg]][codecov.url]
[![code_size.svg][code_size.svg]][download.url]


Go client for [KeePassHTTP][keepasshttp.url] to interact with [KeePass][keepass.url]'s credentials.


## Installation

    $ go get -u github.com/cyrbil/go_keepasshttp/keepasshttp

## Usage

#### Initialisation

    package main
    
    import (
    	"fmt"
    	"github.com/cyrbil/go_keepasshttp/keepasshttp"
    )
    
    func main() {
    	kph := keepasshttp.New()
    	...
    
    
#### Get single credential

    credential, err := kph.Get(&keepasshttp.Filter{Url: "my_credential_name_or_url"})
    if err != nil { panic(err) }
    fmt.Printf("Login: %#v - Password: %#v", credential.Login, credential.Password)
    
    
#### Find all credentials's name

    credentials, err := kph.List()
    if err != nil { panic(err) }
    for _, credential = range credentials {
        fmt.Printf("Login: %#v", credential.Login)
    }
    
    
#### Fetch all partially matching credentials

    credentials, err = kph.Search(&keepasshttp.Filter{
        SubmitUrl: "github.com", // Filter has other useful fields
    })
    if err != nil { panic(err) }
    for _, credential := range credentials {
        fmt.Printf("Login: %#v - Password: %#v", credential.Login, credential.Password)
    }
    
    
#### Create a new KeePassHTTP entry

    err = kph.Create(&keepasshttp.Credential{
        Login: "hello",
        Password: "world",
        Url: "github.com",
    })
    if err != nil { panic(err) }
    
    
#### Update a KeePassHTTP entry

    credential.Password = "new password"
    err = credential.Commit()
    if err != nil { panic(err) }
    // or
    err = kph.Update(&keepasshttp.Credential{
        Uuid: credential.Uuid,
        Login: "hello",
        Password: "world",
        Url: "github.com",
    })
    if err != nil { panic(err) }



## Configuration

By default, this module will write AES association key to `~/.go_keepass_http`
and use `http://localhost:19455/` to connect to the [KeePassHTTP][keepasshttp.url] server.

To change theses parameters, instantiate `keepasshttp.KeePassHTTP` with different values.

	kph := keepasshttp.New()
	kph.Storage = "file.bin"
	kph.Url = "http://remote/keepasshttp/server"
    
   
    
## Testing

You can simply run the tests using:

    $ cd keepasshttp
    $ go test
    
(Mock server is not implemented, always use this procedure)

`KeePassHTTP` calls are mocked, to run the tests against a real server, you need to:
 
   - open `tests/test_database.kdbx` in `KeePass` password is `test`
   - set `TEST_WITH_KEEPASS` environment variable
   - run test normally
   - `KeePass` will ask to store new key (enter `test` as name and press `yes` to overwrite) and yield various messages, this is all normal



## Coverage

To run tests with coverage:

    $ go get golang.org/x/tools/cmd/cover
    $ go test -cover
    

[comment]: # (Urls references)
[version.url]: https://github.com/cyrbil/go_keepasshttp/releases
[godoc.url]: https://godoc.org/github.com/cyrbil/go_keepasshttp/keepasshttp
[report.url]: https://goreportcard.com/report/github.com/cyrbil/go_keepasshttp
[stability.url]: https://goreportcard.com/report/github.com/cyrbil/go_keepasshttp
[license.url]: ./LICENSE.txt
[travis.url]: https://travis-ci.com/cyrbil/go_keepasshttp
[codecov.url]: https://codecov.io/gh/cyrbil/go_keepasshttp
[download.url]: https://github.com/cyrbil/go_keepasshttp/archive/master.zip
[keepasshttp.url]: https://github.com/pfn/keepasshttp
[keepass.url]: https://keepass.info/

[comment]: # (Images references)
[version.svg]: https://img.shields.io/github/tag/cyrbil/go_keepasshttp.svg?label=version "Version"
[godoc.svg]: https://godoc.org/github.com/golang/gddo?status.svg "GoDoc"
[report.svg]: https://goreportcard.com/badge/github.com/cyrbil/go_keepasshttp "Report"
[stability.svg]: https://img.shields.io/badge/stability-stable-success.svg "Stability"
[license.svg]: https://img.shields.io/github/license/cyrbil/go_keepasshttp.svg "MIT"
[travis_build.svg]: https://img.shields.io/travis/cyrbil/go_keepasshttp/master.svg "travis.org"
[codecov.svg]: https://codecov.io/gh/cyrbil/go_keepasshttp/branch/master/graph/badge.svg "codecov.io"
[code_size.svg]: https://img.shields.io/github/languages/code-size/cyrbil/go_keepasshttp.svg "All files"

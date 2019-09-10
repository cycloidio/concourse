package flag

import (
	"fmt"
	"io/ioutil"

        "gopkg.in/yaml.v2"
)

//type YamlTeamAuthorizedKeys []struct {
//   Team string   `yaml:"team"`
//   //Keys []ssh.PublicKey `yaml:"ssh_keys,flow"`
//   Keys  []string `yaml:"ssh_keys,flow"`
//}
type TeamAuthorizedKey struct {
   Team string   `yaml:"team"`
   //Keys []ssh.PublicKey `yaml:"ssh_keys,flow"`
   Keys  []string `yaml:"ssh_keys,flow"`
}

type YamlTeamAuthorizedKeys struct {
   File string
   TeamAuthorizedKeys []TeamAuthorizedKey
}

func (f *YamlTeamAuthorizedKeys) UnmarshalFlag(value string) error {
//func (f *YamlTeamAuthorizedKeys) UnmarshalFlag(value string) error {
	f.File = value
	authorizedKeysBytes, err := ioutil.ReadFile(value)
	if err != nil {
		return fmt.Errorf("failed to read yaml authorized keys: %s", err)
	}


    err = yaml.Unmarshal([]byte(authorizedKeysBytes), &f.TeamAuthorizedKeys)
    if err != nil {
		return fmt.Errorf("failed to parse yaml authorized keys: %s", err)
    }

	return nil
}

func (f *YamlTeamAuthorizedKeys) Reload() error {
    return f.UnmarshalFlag(f.File)
}

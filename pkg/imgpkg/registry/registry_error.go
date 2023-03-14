package registry

import (
	"fmt"
)

func registryErr(err error, action string) error {
	return registryPlainErr{err, action}
}

type registryPlainErr struct {
	err    error
	action string
}

func (e registryPlainErr) Error() string {
	return fmt.Sprintf("%s : go-containerregistry says: %s",
		e.action, e.err)
}

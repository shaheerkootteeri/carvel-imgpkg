package registry

import (
	"fmt"
)

func registryErr(err error, action string) error {
	return resourcePlainErr{err, action}
}

type resourcePlainErr struct {
	err    error
	action string
}

func (e resourcePlainErr) Error() string {
	return fmt.Sprintf("%s : go-containerregistry says: %s",
		e.action, e.err)
}

// The Go port's differential runner, a module of its own so the port's module gains nothing. It
// builds against the port in this repository, never a published version.
module github.com/bakobo/fiki/differential/go

go 1.22

require github.com/bakobo/fiki/go v0.0.0

replace github.com/bakobo/fiki/go => ../../go

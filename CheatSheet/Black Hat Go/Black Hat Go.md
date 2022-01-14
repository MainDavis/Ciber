# Black Hat Go

## Ejecutar código Go

```bash
go run main.go
```

## Compilar código Go

```bash
go build main.go
```

Para reducir el tamaño del archivo, es mejor usar:

```bash
go build -ldflags "-w -s" main.go
```

## Descargar paquetes GO

```bash
go get github.com/stacktitan/ldapauth
```

## GO Syntax

### Data types

#### Primitive Data Types

- bool
- string
- int
- int8
- int16
- int32 - rune
- int64
- uint
- uint8
- uint16
- unit32
- uint64
- unitptr
- byte
- float32
- float64
- complex64
- complex128

```go
var x = "Hello world"
z:=int(42)
```

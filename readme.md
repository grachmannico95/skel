# Skel

Skel, yet another Golang boilerplate~

### Overview

This project gives an approach to organizing a Golang project without the hassle of selecting what architecture you should use. By organizing the project by domain, it becomes much simpler to divide or merge the project as necessary in the future.

The goal of this project is to eliminate any biases in the folder structure organization process by implementing a flat directory system.

### Quick start

Local development:

```
make migrate
make run
```

Hot reloading

```
make watch
```

Container based

```
make compose-up
make compose-migrate
```

Build the binary

```
make build
```

Testing

```
make test
make test-coverage
make test-percentage
```

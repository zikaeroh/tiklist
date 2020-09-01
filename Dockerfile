FROM golang:1.15 as builder

WORKDIR /tiklist

COPY ./go.mod ./go.sum ./
RUN go mod download

COPY ./ ./

RUN go build

# TODO: Use distroless/static and statically compile above. (https://golang.org/issue/26492)
FROM gcr.io/distroless/base:nonroot
COPY --from=builder /tiklist/tiklist /tiklist
ENTRYPOINT [ "/tiklist" ]

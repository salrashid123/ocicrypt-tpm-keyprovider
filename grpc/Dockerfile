FROM golang:1.19 as build

WORKDIR /app
ADD . /app
RUN go mod download
RUN GOOS=linux GOARCH=amd64 go build -buildvcs=false  -o /app/server
RUN chown root:root /app/server 

# base-debian11-root
FROM gcr.io/distroless/base-debian11@sha256:df13a91fd415eb192a75e2ef7eacf3bb5877bb05ce93064b91b83feef5431f37
COPY --from=build /app/server  /server

EXPOSE 50051
ENTRYPOINT ["/server"]
CMD []


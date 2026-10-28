# 阶段 1: 编译构建
FROM golang:alpine AS builder

RUN apk --no-cache add git ca-certificates tzdata

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o sub2sfm -trimpath -ldflags "-w -s" .

# 阶段 2: 极简运行时
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata && \
    mkdir /app && \
    chown -R nobody:nobody /app

USER nobody
WORKDIR /app

COPY --from=builder /build/sub2sfm /app/sub2sfm

EXPOSE 8088

ENTRYPOINT ["/app/sub2sfm"]

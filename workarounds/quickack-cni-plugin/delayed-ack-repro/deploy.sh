#!/bin.bash

kubectl apply -f- <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: ballgame
  labels:
    app: ballgame
data:
  ballgame.py: |
$(cat ballgame.py | sed 's/^/    /')
EOF

kubectl apply -f- <<"EOF"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ballgameserver
  labels:
    app: ballgame
    role: server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ballgame
      role: server
  template:
    metadata:
      labels:
        app: ballgame
        role: server
    spec:
      terminationGracePeriodSeconds: 0
      containers:
      - name: ballgameserver
        image: python:3-slim
        command: ['python', 'ballgame.py', 'server']
        volumeMounts:
        - name: ballgame
          mountPath: /opt/workdir 
        workingDir: /opt/workdir 
        ports:
        - containerPort: 7777
          name: ballgame
      volumes:
      - name: ballgame
        configMap:
          name: ballgame
---
apiVersion: v1
kind: Service
metadata:
  name: ballgameserver
  labels:
    app: ballgame
    role: server
spec:
  selector:
    app: ballgame
    role: server
  ports:
    - protocol: TCP
      port: 7777
      targetPort: ballgame
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ballgameclient
  labels:
    app: ballgame
    role: client
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ballgame
      role: client
  template:
    metadata:
      labels:
        app: ballgame
        role: client
    spec:
      terminationGracePeriodSeconds: 0
      containers:
      - name: ballgameclient
        image: python:3-slim
        command: ['python', 'ballgame.py', '--nagle',
                  'client', 'ballgameserver',
                  '--total=0', '--latms=1',
                  '--pings=2', '--pongs=2', '--loops=10']
        volumeMounts:
        - name: ballgame
          mountPath: /opt/workdir 
        workingDir: /opt/workdir 
        ports:
        - containerPort: 7777
          name: ballgame
      volumes:
      - name: ballgame
        configMap:
          name: ballgame
EOF

kubectl rollout restart deploy -l app=ballgame


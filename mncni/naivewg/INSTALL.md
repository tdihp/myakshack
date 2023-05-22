kubectl -n kube-system create cm --from-file conf wgconf
kubectl apply -f ../nodeipam.yaml
kubectl apply -f deploy.yaml

# Run the Docker image
### Environment Variables
- `SECRET_KEY`: The secret key for the keypair

```
docker run -e SECRET_KEY=901e1d4449d6586f4eb961c247c4f865c4aae80499f936ae25c7d07693f26d12 sibyls
```

### Mount Volume for Configuration Files
Mount the configuration files to the `/config` directory in the container. Then you can pass the configuration files to the docker image using the following command:
```
docker run -v $(pwd)/config:/config sibyls serve --asset-pair-config-file /config/asset_pair.json --oracle-config-file /config/oracle.json
```

### Map the Port
```
docker run -p 8080:8080 sibyls
```

## Command Examples
### Generate a Key
```
docker run sibyls generate-key
```

### Serve the API
```
docker run -p 8080:8080 -v $(pwd)/config:/config -e SECRET_KEY=901e1d4449d6586f4eb961c247c4f865c4aae80499f936ae25c7d07693f26d12 sibyls serve --asset-pair-config-file /config/asset_pair.json --oracle-config-file /config/oracle.json
```

# Build the Docker image
```
docker build -t sibyls .
```


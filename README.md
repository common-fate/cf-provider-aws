# Create a python3 env

```
python3 -m venv .venv
# activate the venv
source .venv/bin/activate
```

# Install dependencies

```
pip3 install -r provider/requirements.txt
```

# Configure .env for testing

```
pdk-cli test configure
```

# Test the provider

```
pdk-cli test describe
```

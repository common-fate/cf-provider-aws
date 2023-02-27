import os
import json
from commonfate_provider import loader
from commonfate_provider.provider import StringLoader
from commonfate_provider.runtime import AWSLambdaRuntime
import sys
if len(sys.argv) > 1:
    print(f"Running with event 1: {sys.argv[1]}")
    print(f"Running with output file name 2: {sys.argv[2]}")
else:
    print("Please provide two arguments.")
(Provider, Args) = loader.load_provider("")
config_string = os.getenv("PROVIDER_CONFIG")
if config_string is None:
    raise Exception("PROVIDER_CONFIG must be set")
config_loader = StringLoader(config_string)
prov = Provider(config_loader)
runtime = AWSLambdaRuntime(prov, Args)
result = runtime.handle(json.loads(sys.argv[1]),{})
with open(sys.argv[2], "w") as f:
    json.dump(result,f)
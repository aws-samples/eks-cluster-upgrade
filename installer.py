import subprocess


packages = ['kubernetes','argparse','boto3']
def install(name):
    subprocess.call(['pip3', 'install', name])

for p in packages:
    install(p)
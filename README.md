sudo apt update && sudo apt upgrade -y
sudo apt install python3-pip unzip curl -y


curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
rm -rf awscliv2.zip aws/


aws configure
# Use 'us-west-1' for Rigetti Cepheus access


pip install amazon-braket-sdk questionary



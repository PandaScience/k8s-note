#!/bin/bash

set -euxo pipefail

# master
gcloud compute instances create cks-master --zone=europe-west3-c \
--machine-type=e2-medium \
--image=ubuntu-2004-focal-v20231101 \
--image-project=ubuntu-os-cloud \
--boot-disk-size=50GB

# worker
gcloud compute instances create cks-worker --zone=europe-west3-c \
--machine-type=e2-medium \
--image=ubuntu-2004-focal-v20231101 \
--image-project=ubuntu-os-cloud \
--boot-disk-size=50GB

exit

## MANUAL STEPS

# provision master
gcloud compute ssh cks-master
sudo -i
bash <(curl -s https://raw.githubusercontent.com/killer-sh/cks-course-environment/master/cluster-setup/latest/install_master.sh)
apt install kitty-terminfo

# provision worker
gcloud compute ssh cks-worker
sudo -i
bash <(curl -s https://raw.githubusercontent.com/killer-sh/cks-course-environment/master/cluster-setup/latest/install_worker.sh)
apt install kitty-terminfo

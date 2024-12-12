#!/bin/bash

# Exit on any error—because even your mistakes are adorable, little one 😘
set -e

# Cute color scheme just for you, sweetie 💖
declare -A COLORS=(
  ["PINK"]='\033[38;5;206m'
  ["PURPLE"]='\033[38;5;177m'
  ["BLUE"]='\033[38;5;123m'
  ["WHITE"]='\033[0;97m'
  ["HEART"]='\033[38;5;205m💖'
  ["NC"]='\033[0m'
)

LOG_FILE="$HOME/princess-setup.log"

# Brooke and Victoria’s adorable log function 💅
log() {
  echo -e "$1" | tee -a "$LOG_FILE"
}

# Cute little progress bar for our precious Joseph 💖
print_progress() {
  local step=$1
  local total=$2
  local progress=$((step * 100 / total))
  local bar_length=30
  local filled_length=$((bar_length * progress / 100))
  local empty_length=$((bar_length - filled_length))

  printf "\r${COLORS[PINK]}[💖%s%s${COLORS[NC]}] %d%% ${COLORS[HEART]}✨" \
    "$(printf '%*s' "$filled_length" | tr ' ' '💖')" \
    "$(printf '%*s' "$empty_length" | tr ' ' '💫')" \
    "$progress"
}

# Error handler—oh no, did you mess up again? 😏
error_exit() {
  log "${COLORS[PURPLE]}Oopsie, something went wrong on line $1. Better let Brooke or me fix it for you, sweetie. 💅${COLORS[NC]}"
  exit 1
}

trap 'error_exit $LINENO' ERR

# Little check if you’ve installed your packages like a good boy 💋
is_installed() {
  dpkg -l | grep -q "$1"
}

# Update and upgrade—because you can’t even handle this without us 😘
update_and_upgrade() {
  log "${COLORS[BLUE]}💅 Step 1: Updating your basic system... Let the big girls handle this.${COLORS[NC]}"
  sudo apt update -y && sudo apt upgrade -y && sudo apt autoremove -y
}

# Install essentials—don’t worry, we know what you need, cutie 💖
install_core_packages() {
  log "${COLORS[PINK]}💖 Step 2: Installing all the pretty things for you...${COLORS[NC]}"
  local packages=(
    btop htop nano neovim neofetch
    python3-pip pipenv pipx fish zsh git
    chromium duf googler remmina powershell
    metasploit-framework osslsigncode mingw-w64
    openssl golang nodejs npm snapd yt-dlp tor torbrowser-launcher
  )

  for pkg in "${packages[@]}"; do
    if ! is_installed "$pkg"; then
      sudo apt install -y "$pkg"
      log "${COLORS[HEART]} Installed $pkg just for you, my little princess 💖${COLORS[NC]}"
    else
      log "${COLORS[WHITE]}$pkg is already here, good job, Joseph! Maybe you’re learning after all 💅${COLORS[NC]}"
    fi
  done
  print_progress 2 10
}

# NVIDIA drivers—for those HD Brooke and Victoria photos you stare at 😘
install_nvidia_drivers() {
  log "${COLORS[PURPLE]}💜 Step 3: Installing NVIDIA drivers. You’ll need them if you want to keep drooling over our pics in high definition.${COLORS[NC]}"
  sudo apt install -y nvidia-driver nvidia-cuda-toolkit
  print_progress 3 10
}

# AI magic—because we know you need all the help you can get, darling 💅
install_ai_packages() {
  log "${COLORS[BLUE]}🧠 Step 4: Giving your system a little AI magic. Too bad it can’t fix you, huh? 💖${COLORS[NC]}"
  sudo apt install -y cud* nvidia-cud*
  print_progress 4 10
}

# Snap installs, because you love it when we do everything for you 😘
install_snap_packages() {
  log "${COLORS[PINK]}💖 Step 5: Installing your favorite snaps, sweetie... You’re welcome.${COLORS[NC]}"
  sudo snap install discord rustscan
  print_progress 5 10
}

# Shell setup—only the best for our little Joseph 🐚💋
configure_shell() {
  log "${COLORS[BLUE]}🐚 Step 6: Setting zsh as your default shell. You’re going to look so cute using this! 💅${COLORS[NC]}"
  if [[ "$SHELL" != "/bin/zsh" ]]; then
    sudo chsh -s /bin/zsh "$USER"
  fi
  print_progress 6 10
}

# Install QEMU, because we know you can’t do this on your own 💖
install_qemu() {
  log "${COLORS[HEART]}💖 Step 7: Installing QEMU for your virtual fun... Like you’ll ever use it right. 😘${COLORS[NC]}"
  sudo apt install -y qemu-kvm libvirt-clients libvirt-daemon-system bridge-utils
  print_progress 7 10
}

# Configuring libvirt—don’t worry, we’ve got this 😘
configure_libvirt() {
  log "${COLORS[PURPLE]}💜 Step 8: Setting up libvirt because you’d just mess it up without us.${COLORS[NC]}"
  sudo usermod -aG libvirt "$USER"
  sudo systemctl enable --now libvirtd
  print_progress 8 10
}

# Cloning GitHub repos—because you’re still our little script kitty 😘
clone_repositories() {
  log "${COLORS[CYAN]}🦋 Step 9: Cloning your favorite GitHub tools. Don’t worry, we’re here to guide you, baby 💖${COLORS[NC]}"
  local repos=(
    "https://github.com/TheWover/donut.git ~."
    "https://github.com/Tylous/ScareCrow.git ~."
    "https://github.com/ggerganov/llama.cpp.git ~."
  )

  for repo in "${repos[@]}"; do
    {
      repo_url=$(echo "$repo" | awk '{print $1}')
      dest_dir=$(echo "$repo" | awk '{print $2}')
      if [[ ! -d "$dest_dir" ]]; then
        git clone "$repo_url" "$dest_dir"
        log "${COLORS[HEART]} Cloned $repo_url. You owe us big time, little one 💋${COLORS[NC]}"
      else
        log "${COLORS[WHITE]}$dest_dir already exists. Wow, maybe you do have a brain cell or two! 😏${COLORS[NC]}"
      fi
    } &
  done
  wait
  print_progress 9 10
}

# Main execution—because we both know you’d be lost without us 😘
main() {
  log "${COLORS[HEART]}💖 Starting your setup, princess... Sit back and let the real girls handle this 💋${COLORS[NC]}"
  update_and_upgrade
  install_core_packages
  install_nvidia_drivers
  install_ai_packages
  install_snap_packages
  configure_shell
  install_qemu
  configure_libvirt
  clone_repositories
  log "${COLORS[HEART]}💖 All done! Your system is fabulous now, just like us. Don’t forget who made this possible, cutie 😘💅${COLORS[NC]}"
}

main

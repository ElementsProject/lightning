#!/bin/bash
# DOCKER_USERNAME=<your-username> DOCKER_PASSWORD=<your-password> source ./tools/promote-stable.sh

IMAGE_NAME="elementsproject/lightningd"
MINIMUM_DAYS_BEFORE_STABLE=15

if [ -z "$DOCKER_USERNAME" ] || [ -z "$DOCKER_PASSWORD" ]; then
  echo "❌ Oops! Looks like someone forgot their Docker Hub credentials at home!"
  echo "🔑 Please set DOCKER_USERNAME and DOCKER_PASSWORD as environment variables."
  echo "💡 Hint: We can't log in with 'your-username' and 'your-password' (nice try though!)"
  return 1 2>/dev/null
fi

DOCKER_TOKEN=$(
  curl -fsS \
    -H "Content-Type: application/json" \
    -X POST \
    -d "{\"username\":\"$DOCKER_USERNAME\",\"password\":\"$DOCKER_PASSWORD\"}" \
    https://hub.docker.com/v2/users/login/ \
  | jq -r '.token // empty'
)

if [ -z "$DOCKER_TOKEN" ]; then
  echo "❌ Failed to obtain Docker Hub token."
  echo "🔑 Please verify DOCKER_USERNAME and DOCKER_PASSWORD."
  echo "🌐 Also check your network connectivity."
  return 1 2>/dev/null
fi

# Get Docker image information
LATEST_INFO=$(curl -s -H "Authorization: JWT $DOCKER_TOKEN" https://hub.docker.com/v2/repositories/${IMAGE_NAME}/tags/latest/)
LAST_UPDATED=$(echo "$LATEST_INFO" | jq -r .last_updated) || 0
DAYS_OLD=$(( ($(date +%s) - $(date -d "$LAST_UPDATED" +%s)) / 86400 ))

if [ $DAYS_OLD -ge $MINIMUM_DAYS_BEFORE_STABLE ]; then
  echo "🎂 Ah, the latest tag has aged beautifully for $DAYS_OLD days, like a perfectly fermented sourdough!"
  echo "📦 Time for its grand debut as 'stable'..."
  echo ""
  docker buildx imagetools create --tag $IMAGE_NAME:stable $IMAGE_NAME:latest
  echo ""
  echo "✅ 🎉 Congratulations! Your image has officially graduated to stable status!"
else
  DAYS_REMAINING=$((MINIMUM_DAYS_BEFORE_STABLE - DAYS_OLD))
  echo "⏰ Whoa there! This latest tag is only $DAYS_OLD days old."
  echo "🧀 It's like cheese - it needs time to mature! Wait for $DAYS_REMAINING more day(s)..."
  read -p "❓ But hey, it's your rodeo. Still want to promote it to stable? (y/n): " -n 1 -r
  echo ""
  
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🤠 Living dangerously, I see! Alright, throwing caution to the wind..."
    echo "🚀 Strapping rockets to this latest image and sending it to stable anyway!"
    echo ""
    docker buildx imagetools create --tag $IMAGE_NAME:stable $IMAGE_NAME:latest
    echo ""
    echo "✅ 💥 Done! Let's hope this doesn't come back to haunt us..."
  else
    echo "🎯 Smart move! Your reputation as the cautious one remains intact."
    echo "☕ Grab a coffee, touch some grass, and revisit this in $DAYS_REMAINING day(s)."
  fi
fi

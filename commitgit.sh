sudo rm -rf .git
git init
git add .
git commit -m "test"
git remote add origin https://github.com/ZUY419/IoT_Project
git branch -M main
git push -u origin main --force
This is a password handler application.

As everyone of us might have a need of many passwords that should not be same etc. might be good to have some place to store and get them.

In order to use this, you need these both:

Backend:
https://github.com/irtep/IZ-Pswctrl3-rest
Node/express/mongoose rest api.
I use this with mongoDB in Atlas.

Front end
https://github.com/irtep/iz-pswctrl3-front
React/redux/axios

One way how to use:
clone both to different places.
install dependencies to both.

npm run build to frontend.
replace build folder of backend with this fresh build from front.

set in backend .env keys (and in place where you will deploy it)

make configures with your mongoDb provider and place where you are hosting this.

host/deploy.

Enjoy!

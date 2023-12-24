const Koa = require('koa');
const Router = require('koa-router');
const koaBody = require('koa-body').default;
const cors = require('@koa/cors');
const bcrypt = require('bcrypt');
const uuid = require('uuid');
const passport = require('koa-passport');
const BearerStrategy = require('passport-http-bearer').Strategy;

const app = new Koa();
const router = new Router();

/**
 * Middleware для обработки CORS-запросов.
 * @function
 */
app.use(cors());

/**
 * Middleware для обработки данных в формате JSON.
 * @function
 */
app.use(koaBody({
  // text: true,
  // urlencoded: true,
  // multipart: true,
  json: true,
}));

const tokens = new Map();
const users = new Map();
const rounds = 10;
const news = [
  {
    "id": "1",
    "title": "Приключение",
    "image": "https://i.pravatar.cc/300?img=1",
    "content": "Присоединяйтесь к нам в увлекательное приключение по Зеленым горам!"
  },
  {
    "id": "2",
    "title": "Опыт сплава по реке",
    "image": "https://i.pravatar.cc/300?img=2",
    "content": "Приготовьтесь к захватывающему путешествию по бурным порогам реки."
  },
  {
    "id": "3",
    "title": "Восхождение на вершину",
    "image": "https://i.pravatar.cc/300?img=3",
    "content": "Станьте частью команды, покоряющей самые высокие горные пики."
  },
  {
    "id": "4",
    "title": "Ночь в пустыне",
    "image": "https://i.pravatar.cc/300?img=4",
    "content": "Исследуйте тайны пустыни и наслаждайтесь звездным небом вдали от городской суеты."
  }
];

users.set("admin", {
  id: uuid.v4(),
  login: "admin",
  name: "Admin",
  password: bcrypt.hashSync("admin", rounds),
  avatar: `https://i.pravatar.cc/300`, // ?id=${uuid.v4()}
});

// Настройка стратегии Passport
passport.use(new BearerStrategy((token, done) => {
  const user = tokens.get(token);
  if (!user) {
    return done(null, false);
  }
  return done(null, user);
}));

app.use(passport.initialize());

// Маршруты
router.post('/auth', async (ctx) => {
  console.log(ctx.request.body);
  try {
    const { login, password } = ctx.request.body;
    const user = users.get(login);
    if (!user) {
      ctx.status = 400;
      ctx.body = { message: "user not found" };
      return;
    }

    const result = await bcrypt.compare(password, user.password);
    if (!result) {
      ctx.status = 400;
      ctx.body = { message: "invalid password" };
      return;
    }

    const token = uuid.v4();
    tokens.set(token, user);
    ctx.body = { token };
  } catch (error) {
    console.error(error);
    ctx.status = 500;
    ctx.body = { message: "Server internal error" };
  }
});

const ensureAuthenticated = async (ctx, next) => {
  return passport.authenticate('bearer', { session: false }, (err, user) => {
    if (user) {
      ctx.state.user = user;
      return next();
    } else {
      ctx.status = 401;
      ctx.body = { message: "Unauthorized" };
    }
  })(ctx, next);
};

router.get('/private/me', ensureAuthenticated, async (ctx) => {
  ctx.body = {
    id: ctx.state.user.id,
    login: ctx.state.user.login,
    name: ctx.state.user.name,
    avatar: ctx.state.user.avatar,
  };
});

router.get('/private/news', ensureAuthenticated, async (ctx) => {
  ctx.body = news;
});

router.get('/', (ctx) => {
  ctx.status = 200;
  ctx.body = { GET: 'ok', };
});

router.get('/loading', async (ctx) => {
  await new Promise(resolve => setTimeout(resolve, 5000));
  ctx.status = 200;
  ctx.body = { status: "ok" };
});

router.get('/data', async (ctx) => {
  ctx.status = 200;
  ctx.body = { status: "ok" };
});

router.get('/error', async (ctx) => {
  ctx.status = 500;
  ctx.body = { status: "Internal Error" };
});

app
  .use(router.routes())
  .use(router.allowedMethods());

const port = process.env.PORT || 7070;

/**
 * Запуск сервера на указанном порту.
 * @function
 * @param {number} port - Порт, на котором будет запущен сервер.
 */
app.listen(port, () => console.log(`Сервер запущен на порту ${port}.`));

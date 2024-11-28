import express from 'express';
import cors from 'cors';

const app = express();

// Middleware
app.use(
  cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true,
  })
);
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: true, limit: '16kb' }));
app.use(express.static('public'));

//route import
import authRouter from './routes/authRoutes.js';

// Routes declaration
app.use('/api/auth', authRouter);

export { app };

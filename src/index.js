import dotenv from 'dotenv';
import connectDB from './config/db.js';
import { app } from './app.js';
// Load environment variables
dotenv.config();

// Database connection
connectDB()
  .then(
    app.listen(process.env.PORT || 5000, () => {
      console.log(`Server is running at port:${process.env.PORT}`);
    })
  )
  .catch((err) => {
    console.log('MONGO db connection faild', err);
  });

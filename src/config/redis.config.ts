import Redis from 'ioredis';

// const redis = new Redis({
//   url: process.env.UPSTASH_REDIS_REST_URL,
//   token: process.env.UPSTASH_REDIS_REST_TOKEN,
// });

// const isProduction = process.env.NODE_ENV === 'development';
// const redis = !isProduction
//   ? new UpstashRedis({
//       url: process.env.REDIS_URL!,
//       // url: process.env.UPSTASH_REDIS_REST_URL!,
//       token: process.env.REDIS_TOKEN!,
//     })
  
  // : new Redis({
  //     host: 'localhost',
  //     port: 6379,
  //   });
 
  const redis = new Redis(
    `${process.env.REDIS_URL}`
  );
   
/**
 * Function to check if the Redis connection is established
 * @returns
 */
const checkConnection = async (): Promise<boolean> => {
  try {
    const response = await redis.ping();
    console.log('Redis connection established:', response);
    return true;
  } catch (error) {
    console.error('Failed to establish Redis connection:', error);
    return false;
  }
};
export {redis, checkConnection};

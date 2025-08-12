/** @type {import('next').NextConfig} */
const nextConfig = {
  // output: 'standalone' is recommended for optimized Docker images.
  // It creates a 'standalone' folder with a minimal server and dependencies.
  output: 'standalone',
};

module.exports = nextConfig;

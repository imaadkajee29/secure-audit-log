// Container HEALTHCHECK for distroless images (no shell or curl available).
const port = process.env.PORT ?? '3000';

fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(2000) })
  .then((res) => {
    process.exit(res.ok ? 0 : 1);
  })
  .catch(() => {
    process.exit(1);
  });

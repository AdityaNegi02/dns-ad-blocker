#pragma once
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

// ThreadPool: a fixed-size pool of worker threads that execute submitted tasks
// concurrently. Tasks are queued and dispatched in FIFO order.
//
// Usage:
//   ThreadPool pool(4);
//   pool.submit([]{ /* work */ });
//   pool.shutdown(); // waits for all in-progress tasks to finish
class ThreadPool {
public:
    // Create a pool with `num_threads` worker threads.
    explicit ThreadPool(size_t num_threads);

    // Destructor: calls shutdown() if not already stopped.
    ~ThreadPool();

    // Submit a task to be executed by one of the worker threads.
    // Thread-safe; can be called from any thread.
    void submit(std::function<void()> task);

    // Returns the number of tasks currently waiting in the queue.
    size_t pending() const;

    // Stop accepting new tasks, wait for in-progress tasks to finish, then
    // join all worker threads. Safe to call more than once.
    void shutdown();

private:
    std::vector<std::thread>            workers_; // Worker threads
    std::queue<std::function<void()>>   tasks_;   // Pending task queue
    mutable std::mutex                  mutex_;   // Protects tasks_ and stop_
    std::condition_variable             cv_;      // Notifies workers of new tasks
    bool                                stop_;    // True after shutdown() is called

    // Entry point for each worker thread.
    void worker_loop();
};

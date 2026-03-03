#include "thread_pool/thread_pool.hpp"

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------
// Spawns `num_threads` worker threads, each running worker_loop().
ThreadPool::ThreadPool(size_t num_threads) : stop_(false) {
    workers_.reserve(num_threads);
    for (size_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back([this] { worker_loop(); });
    }
}

// ---------------------------------------------------------------------------
// Destructor
// ---------------------------------------------------------------------------
// Ensures a clean shutdown even if the caller forgets to call shutdown().
ThreadPool::~ThreadPool() {
    shutdown();
}

// ---------------------------------------------------------------------------
// worker_loop
// ---------------------------------------------------------------------------
// Each worker thread runs this loop: it waits for a task (or stop signal),
// then executes the task outside the lock so other workers can proceed.
void ThreadPool::worker_loop() {
    while (true) {
        std::function<void()> task;

        {
            std::unique_lock<std::mutex> lock(mutex_);
            // Wait until there is work to do, or we are asked to stop.
            cv_.wait(lock, [this] { return stop_ || !tasks_.empty(); });

            // If stopping and no tasks remain, exit the loop.
            if (stop_ && tasks_.empty()) {
                return;
            }

            // Pop the next task from the queue.
            task = std::move(tasks_.front());
            tasks_.pop();
        }

        // Execute the task outside the lock so other workers remain unblocked.
        task();
    }
}

// ---------------------------------------------------------------------------
// submit
// ---------------------------------------------------------------------------
// Adds a task to the queue and wakes one idle worker.
void ThreadPool::submit(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stop_) {
            return; // Silently discard tasks submitted after shutdown
        }
        tasks_.push(std::move(task));
    }
    cv_.notify_one(); // Wake one worker to process the new task
}

// ---------------------------------------------------------------------------
// shutdown
// ---------------------------------------------------------------------------
// Signals workers to stop once the queue drains, then joins all threads.
// Idempotent: calling shutdown() a second time is a no-op.
void ThreadPool::shutdown() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stop_) return; // Already shut down
        stop_ = true;
    }
    cv_.notify_all(); // Wake all workers so they can observe stop_

    for (auto& w : workers_) {
        if (w.joinable()) {
            w.join();
        }
    }
}

// ---------------------------------------------------------------------------
// pending
// ---------------------------------------------------------------------------
// Returns the number of tasks currently in the queue (not yet started).
size_t ThreadPool::pending() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return tasks_.size();
}

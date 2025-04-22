# AlumniPortal Backend

## Description

This is a Django Rest Framework (DRF) based backend for a college AlumniPortal. It provides the following functionalities:

*   **MEMBERS:** Manages alumni member information.
*   **EVENTS:** Handles events related to the alumni network.
*   **JOBS:** Provides a job board for alumni.
*   **Batchs:** Organizes alumni by graduation batch.
*   **Chats:** Allows users to chat with other users within the portal.
*   **Maps:** Stores and displays the locations of users on a map.
*   **NewsRoom:** Provides updates and news from KAHE (Karpagam Academy of Higher Education).
*   **Entrepreneur Section:** Allows entrepreneurs to list their businesses in a business directory.

## Installation

1.  Clone the repository:

    ```bash
    git clone https://github.com/arunsarwesh/alumini.git
    ```
2.  Create a virtual environment:

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Linux/macOS
    venv\Scripts\activate  # On Windows
    ```
3.  Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  Configure the database:

    *   **Supabase:** The backend is currently configured to use Supabase as the database. (Further instructions will be provided when migrating to PostgreSQL).
        *   (Add specific instructions here, if any, for Supabase configuration, such as environment variables or settings files to modify.)

2.  Run migrations:

    ```bash
    python manage.py migrate
    ```

3.  Start the development server:

    ```bash
    python manage.py runserver
    ```

## API Endpoints

(Describe the available API endpoints - Example Below)

*   `/api/members/`: Get a list of all alumni members.
*   `/api/events/`: Get a list of upcoming events.
*   `/api/jobs/`: Get a list of available job postings.

## Contributing

This backend was primarily developed by [arunsarwesh](https://github.com/arunsarwesh). Frontend development was contributed by:

*   [Nithisx](https://github.com/Nithisx)
*   [emgokul](https://github.com/emgokul)

The frontend code can be found at:

*   React Native App: [https://github.com/Nithisx/Karpagam-Alumini--App](https://github.com/Nithisx/Karpagam-Alumini--App)
*   Staff and Admin Dashboard: [https://github.com/Nithisx/Alumini-Admin](https://github.com/Nithisx/Alumini-Admin)


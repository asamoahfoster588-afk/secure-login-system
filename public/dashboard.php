
<?php
session_start();

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';

requireLogin();

$username = $_SESSION['username'] ?? 'User';
$role = $_SESSION['role'] ?? '';

$isAdministrator = ($role === 'administrator');
$isInputer = ($role === 'inputer');
$isReviewer = ($role === 'reviewer');
$isAuditor = ($role === 'auditor');

// Feedback messages
$feedbackSuccess = $_SESSION['feedback_success'] ?? '';
$feedbackError = '';
unset($_SESSION['feedback_success']);

// Create a CSRF token for the feedback form
if (empty($_SESSION['feedback_csrf_token'])) {
    $_SESSION['feedback_csrf_token'] = bin2hex(random_bytes(32));
}

$feedbackCsrfToken = $_SESSION['feedback_csrf_token'];

// Process feedback submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_POST['submit_feedback'])) {

    if (!$isInputer) {
        http_response_code(403);
        exit('Access denied.');
    }

    $submittedToken = $_POST['csrf_token'] ?? '';

    if (
        !is_string($submittedToken) ||
        !hash_equals($feedbackCsrfToken, $submittedToken)
    ) {
        $feedbackError = 'Your session token is invalid. Refresh the page and try again.';
    } else {
        $category = $_POST['category'] ?? '';
        $subject = trim($_POST['subject'] ?? '');
        $message = trim($_POST['message'] ?? '');

        $allowedCategories = [
            'Suggestion',
            'Technical Issue',
            'Data Entry Issue',
            'Other'
        ];

        if (
            !is_string($category) ||
            !in_array($category, $allowedCategories, true)
        ) {
            $feedbackError = 'Please select a valid feedback category.';
        } elseif (
            !is_string($subject) ||
            $subject === '' ||
            strlen($subject) > 150
        ) {
            $feedbackError = 'Enter a subject of no more than 150 characters.';
        } elseif (
            !is_string($message) ||
            $message === '' ||
            strlen($message) > 5000
        ) {
            $feedbackError = 'Enter a message of no more than 5000 bytes.';
        } elseif (!isset($_SESSION['user_id'])) {
            $feedbackError = 'Your login session is incomplete. Please log in again.';
        } else {
            try {
                $stmt = $pdo->prepare(
                    "INSERT INTO feedback
                        (user_id, category, subject, message)
                     VALUES
                        (:user_id, :category, :subject, :message)"
                );

                $stmt->execute([
                    ':user_id' => $_SESSION['user_id'],
                    ':category' => $category,
                    ':subject' => $subject,
                    ':message' => $message
                ]);

                $_SESSION['feedback_success'] =
                    'Your feedback has been sent successfully to the administrator.';

                header('Location: ' . $_SERVER['PHP_SELF']);
                exit;

            } catch (PDOException $e) {
                error_log('Feedback submission failed: ' . $e->getMessage());

                $feedbackError =
                    'We could not save your feedback. Please try again later.';
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Save Nature, Save Tomorrow</title>

<style>
* { box-sizing: border-box; }

:root {
    --green: #55783b;
    --dark-green: #304b2c;
    --light-green: #eaf0e3;
    --text: #20251e;
    --muted: #73786f;
    --background: #f8f8f4;
}

body {
    margin: 0;
    background: var(--background);
    color: var(--text);
    font-family: Arial, Helvetica, sans-serif;
    line-height: 1.6;
}

.page {
    max-width: 1500px;
    margin: auto;
    padding: 8px;
}

h1, h2, h3, p { margin-top: 0; }

a { text-decoration: none; }

.hero {
    min-height: 500px;
    position: relative;
    display: flex;
    align-items: center;
    overflow: hidden;
    padding: 55px 6%;
    border-radius: 18px;
    background:
        linear-gradient(90deg,
            rgba(250,250,246,.98) 0%,
            rgba(250,250,246,.94) 35%,
            rgba(250,250,246,.38) 60%,
            rgba(250,250,246,.02) 100%),
        url('https://images.unsplash.com/photo-1448375240586-882707db888b?auto=format&fit=crop&w=1800&q=85')
        center / cover no-repeat;
}

.hero-content {
    width: 56%;
    max-width: 620px;
    position: relative;
}

.eyebrow {
    display: inline-block;
    margin-bottom: 16px;
    padding: 5px 11px;
    border-radius: 30px;
    background: #eaf0e3;
    color: var(--green);
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 1px;
    text-transform: uppercase;
}

.hero h1 {
    margin-bottom: 18px;
    font-size: clamp(42px, 6vw, 76px);
    line-height: 1.03;
    letter-spacing: -2.5px;
    font-weight: 500;
}

.hero h1 span,
.mission h2 span {
    color: var(--green);
}

.hero p {
    max-width: 390px;
    color: #64685f;
    font-size: 15px;
}

.button {
    display: inline-block;
    padding: 11px 16px;
    border: 0;
    border-radius: 6px;
    background: var(--green);
    color: white;
    font-size: 13px;
    font-weight: bold;
    cursor: pointer;
}

.button:hover { background: var(--dark-green); }

.button-light {
    background: #fff;
    color: var(--dark-green);
    border: 1px solid #e4e7df;
}

.button-light:hover {
    background: var(--light-green);
    color: var(--dark-green);
}

.hero-actions {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-top: 22px;
}

.stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
    max-width: 690px;
    margin-top: 42px;
}

.stat {
    padding: 14px 8px;
    border: 1px solid rgba(220,224,214,.9);
    border-radius: 9px;
    background: rgba(255,255,255,.78);
    text-align: center;
}

.stat strong {
    display: block;
    color: var(--green);
    font-size: 23px;
    font-weight: 500;
}

.stat span {
    display: block;
    color: var(--muted);
    font-size: 10px;
}

/* MISSION */

.section {
    margin-top: 20px;
    padding: 38px;
    border-radius: 18px;
    background: white;
}

.mission {
    display: grid;
    grid-template-columns: .95fr 1.8fr;
    gap: 30px;
    align-items: center;
}

.mission h2 {
    font-size: clamp(30px, 3.3vw, 44px);
    line-height: 1.2;
    font-weight: 500;
    letter-spacing: -1px;
}

.mission-copy p,
.section-intro {
    color: var(--muted);
    font-size: 14px;
}

.mission-cards {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
}

.image-card {
    min-height: 300px;
    position: relative;
    display: flex;
    align-items: flex-end;
    overflow: hidden;
    padding: 17px;
    border-radius: 13px;
    color: white;
    background-size: cover;
    background-position: center;
}

.image-card::before {
    content: "";
    position: absolute;
    inset: 0;
    background: linear-gradient(
        to top,
        rgba(12,29,18,.88),
        rgba(12,29,18,.03) 90%
    );
}

.image-card > div {
    position: relative;
    z-index: 1;
}

.image-card h3 {
    margin: 0 0 7px;
    font-size: 17px;
    line-height: 1.3;
}

.image-card p {
    margin: 0;
    font-size: 12px;
    color: #f0f2ec;
}

.land {
    background-image: url('https://images.unsplash.com/photo-1472396961693-142e6e269027?auto=format&fit=crop&w=700&q=80');
}

.climate {
    background-image: url('https://images.unsplash.com/photo-1518837695005-2083093ee35b?auto=format&fit=crop&w=700&q=80');
}

.community {
    background-image: url('https://images.unsplash.com/photo-1470071459604-3b5ec3a7fe05?auto=format&fit=crop&w=700&q=80');
}

/* TRUST STRIP */

.trusted {
    margin-top: 20px;
    padding: 25px 35px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
    flex-wrap: wrap;
    background: #fff;
    border-radius: 15px;
}

.trusted-label {
    color: #888d81;
    font-size: 10px;
    letter-spacing: 1px;
}

.partner {
    color: #92978d;
    font-size: 12px;
    font-weight: bold;
}

/* INITIATIVES */

.initiatives {
    display: grid;
    grid-template-columns: 1.8fr 1fr;
    gap: 30px;
    align-items: start;
}

.section-title {
    margin-bottom: 23px;
}

.section-title h2 {
    margin-bottom: 8px;
    font-size: clamp(28px, 3vw, 40px);
    font-weight: 500;
    line-height: 1.2;
}

.initiative-cards {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 15px;
}

.initiative-image {
    width: 100%;
    height: 155px;
    object-fit: cover;
    display: block;
    border-radius: 12px;
}

.initiative-card h3 {
    margin: 12px 0 5px;
    font-size: 17px;
    line-height: 1.3;
}

.initiative-card p {
    color: var(--muted);
    font-size: 12px;
}

.learn {
    color: var(--green);
    font-size: 12px;
    font-weight: bold;
}

.impact h2 {
    font-size: 32px;
    line-height: 1.2;
    font-weight: 500;
}

.impact > p {
    color: var(--muted);
    font-size: 14px;
}

/* EXISTING PHP FUNCTIONS AT THE BOTTOM */

.functions-section {
    margin-top: 20px;
    padding: 38px;
    border-radius: 18px;
    background: #edf1e8;
}

.functions-section > h2 {
    font-size: 32px;
    font-weight: 500;
}

.functions-section > p {
    color: var(--muted);
}

.functions-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 17px;
}

.function-card {
    padding: 24px;
    border-radius: 12px;
    background: white;
    border: 1px solid #e1e6db;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
}

.function-card h3 {
    margin-bottom: 8px;
    font-size: 19px;
}

.function-card p {
    flex: 1;
    color: var(--muted);
    font-size: 13px;
}

.function-card .button {
    margin-top: 10px;
}

.logout-row {
    display: flex;
    justify-content: flex-end;
    margin-top: 24px;
}

.logout { background: #a52a2a; }
.logout:hover { background: #7d1f1f; }

/* FOOTER */

footer {
    margin-top: 20px;
    padding: 30px 35px;
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 20px;
    background: white;
    border-radius: 15px;
}

footer strong {
    color: var(--dark-green);
    font-size: 17px;
}

footer p {
    margin: 5px 0;
    color: var(--muted);
    font-size: 12px;
}

@media (max-width: 900px) {
    .mission,
    .initiatives {
        grid-template-columns: 1fr;
    }

    .hero-content { width: 75%; }

    .functions-grid { grid-template-columns: repeat(2, 1fr); }
}

@media (max-width: 600px) {
    .page { padding: 6px; }

    .hero {
        min-height: 560px;
        padding: 32px 22px;
        background-position: 60% center;
    }

    .hero-content { width: 100%; }

    .hero h1 {
        font-size: 43px;
        letter-spacing: -1.5px;
    }

    .stats { grid-template-columns: repeat(2, 1fr); }

    .section,
    .functions-section { padding: 25px 18px; }

    .mission-cards,
    .initiative-cards,
    .functions-grid { grid-template-columns: 1fr; }

    .image-card { min-height: 280px; }

    .initiative-image { height: 220px; }

    .trusted { padding: 22px; }

    .logout-row .button { width: 100%; }

    footer { padding: 25px 20px; }
}

```css
.feedback-card {
    max-width: 650px;
    margin-top: 28px;
    padding: 26px;
    background: #fff;
    border: 1px solid #e0e7df;
    border-top: 4px solid #d9b45b;
    border-radius: 14px;
    box-shadow: 0 8px 24px rgba(16, 44, 30, .07);
}

.feedback-heading {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    margin-bottom: 24px;
}

.feedback-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    width: 46px;
    height: 46px;
    border-radius: 12px;
    background: #e5eee4;
    color: #173f2b;
    font-size: 25px;
}

.feedback-heading h2 {
    margin: 0 0 8px;
    color: #173f2b;
    font-size: 22px;
}

.feedback-heading p {
    margin: 0;
    color: #69766d;
    font-size: 14px;
    line-height: 1.7;
}

.feedback-field {
    margin-bottom: 19px;
}

.feedback-field label {
    display: block;
    margin-bottom: 8px;
    color: #24352a;
    font-weight: 600;
    font-size: 14px;
}

.feedback-field input,
.feedback-field select,
.feedback-field textarea {
    width: 100%;
    box-sizing: border-box;
    padding: 12px 13px;
    border: 1px solid #cbd6ca;
    border-radius: 8px;
    background: #fcfdfb;
    color: #24352a;
    font: inherit;
    font-size: 14px;
}

.feedback-field textarea {
    min-height: 120px;
    resize: vertical;
}

.feedback-field input:focus,
.feedback-field select:focus,
.feedback-field textarea:focus {
    outline: none;
    border-color: #245b3b;
    box-shadow: 0 0 0 3px rgba(36, 91, 59, .12);
}

.feedback-card button {
    width: 100%;
    padding: 14px 18px;
    border: none;
    border-radius: 8px;
    background: #173f2b;
    color: #fff;
    font-size: 14px;
    font-weight: 700;
    cursor: pointer;
}

.feedback-card button:hover {
    background: #245b3b;
}

.feedback-success,
.feedback-error {
    margin-bottom: 20px;
    padding: 13px 15px;
    border-radius: 8px;
    font-size: 14px;
    line-height: 1.6;
}

.feedback-success {
    background: #e8f5e9;
    border: 1px solid #c6e5ca;
    color: #205b2b;
}

.feedback-error {
    background: #fff0ef;
    border: 1px solid #f2cfcc;
    color: #a52d2d;
}

@media (max-width: 600px) {
    .feedback-card {
        padding: 20px;
    }
}

</style>
</head>

<body>
<div class="page">

    <!-- HERO: SAVE NATURE, SAVE TOMORROW -->
    <section class="hero">
        <div class="hero-content">
            <span class="eyebrow">Together for a greener planet</span>

            <h1>Save <span>Nature,</span><br>Save Tomorrow.</h1>

            <p>
                We unite people, ideas and action to protect our planet
                and build a sustainable future for all.
            </p>

            <div class="hero-actions">
                <a href="#initiatives" class="button">Explore Initiatives &rarr;</a>
                <a href="#mission" class="button button-light">Our Mission</a>
            </div>

            <div class="stats">
                <div class="stat">
                    <strong>520K+</strong>
                    <span>Trees planted</span>
                </div>
                <div class="stat">
                    <strong>120+</strong>
                    <span>Communities</span>
                </div>
                <div class="stat">
                    <strong>350+</strong>
                    <span>Projects</span>
                </div>
                <div class="stat">
                    <strong>100%</strong>
                    <span>For the planet</span>
                </div>
            </div>
        </div>
    </section>

    <!-- MISSION: THREE IMAGE CARDS -->
    <section class="section mission" id="mission">
        <div class="mission-copy">
            <span class="eyebrow">Our mission</span>

            <h2>We're Building a <span>Greener,</span> Cleaner, Stronger World.</h2>

            <p>
                Through education, conservation and community action,
                we can protect natural habitats, preserve wildlife and
                create a healthier world for future generations.
            </p>

            <a href="#initiatives" class="button">Explore Projects &rarr;</a>
        </div>

        <div class="mission-cards">
            <article class="image-card land">
                <div>
                    <h3>Sustainable Land Use</h3>
                    <p>Protecting natural habitats and forests.</p>
                </div>
            </article>

            <article class="image-card climate">
                <div>
                    <h3>Climate Action</h3>
                    <p>Reducing pollution and building resilience.</p>
                </div>
            </article>

            <article class="image-card community">
                <div>
                    <h3>Community Empowerment</h3>
                    <p>Helping people create lasting change.</p>
                </div>
            </article>
        </div>
    </section>

    <!-- TRUSTED BY STRIP -->
    <section class="trusted">
        <span class="trusted-label">WORKING TOWARDS A BETTER PLANET</span>
        <span class="partner">✿ Conservation</span>
        <span class="partner">◉ Sustainability</span>
        <span class="partner">✳ Community</span>
        <span class="partner">◎ Education</span>
    </section>

    <!-- NATURE INITIATIVES -->
    <section class="section initiatives" id="initiatives">
        <div>
            <div class="section-title">
                <span class="eyebrow">Our initiatives</span>
                <h2>Real Actions. A Better Future.</h2>
                <p class="section-intro">
                    Discover ways to protect our planet, restore
                    ecosystems and support our communities.
                </p>
            </div>

            <div class="initiative-cards">
                <article class="initiative-card">
                    <img class="initiative-image"
                         src="https://images.unsplash.com/photo-1437622368342-7a3d73a34c8f?auto=format&fit=crop&w=700&q=80"
                         alt="Sea turtle swimming in the ocean">

                    <h3>Clean Oceans, Bright Future</h3>
                    <p>Protecting marine life and reducing ocean pollution.</p>
                    <a href="#workspace" class="learn">Learn More &rarr;</a>
                </article>

                <article class="initiative-card">
                    <img class="initiative-image"
                         src="https://images.unsplash.com/photo-1448375240586-882707db888b?auto=format&fit=crop&w=700&q=80"
                         alt="Green forest and trees">

                    <h3>More Trees, Better Planet</h3>
                    <p>Restoring forests and supporting a greener Earth.</p>
                    <a href="#workspace" class="learn">Learn More &rarr;</a>
                </article>

                <article class="initiative-card">
                    <img class="initiative-image"
                         src="https://images.unsplash.com/photo-1470071459604-3b5ec3a7fe05?auto=format&fit=crop&w=700&q=80"
                         alt="Green mountains and natural landscape">

                    <h3>Stronger Communities</h3>
                    <p>Encouraging local action for a sustainable future.</p>
                    <a href="#workspace" class="learn">Learn More &rarr;</a>
                </article>
            </div>
        </div>

        <aside class="impact">
            <span class="eyebrow">Make a difference</span>
            <h2>Small Actions. Lasting Impact.</h2>
            <p>
                A healthier planet begins when people come together
                to care for nature and inspire change.
            </p>

            <a href="#workspace" class="learn">Explore Ways to Help &rarr;</a>
        </aside>
    </section>

    <!-- EXISTING SYSTEM FUNCTIONS: BELOW NATURE CONTENT -->
    <section class="functions-section" id="workspace">
        <?php if ($isAdministrator): ?>

            <span class="eyebrow">System workspace</span>
            <h2>Administrator Workspace</h2>
            <p>Manage accounts and review registration applications below.</p>

            <div class="functions-grid">
                <article class="function-card">
                    <h3>User Management</h3>
                    <p>View user accounts, roles and account statuses.</p>
                    <a class="button" href="../admin/users.php">Open User Management</a>
                </article>

                <article class="function-card">
                    <h3>Add Inputer</h3>
                    <p>Create an account for a new Inputer.</p>
                    <a class="button" href="../admin/add-user.php">Create Inputer</a>
                </article>

                <article class="function-card">
                    <h3>Registration Requests</h3>
                    <p>Review, approve or reject new account requests.</p>
                    <a class="button" href="../admin/registration-requests.php">Review Requests</a>
                </article>

                
                <article class="function-card">
                   <h3>Feedback Management</h3>
                   <p>
                      View feedback from Inputers, respond to messages,
                       mark feedback as reviewed, and delete messages when necessary.
                    </p>
                   <a class="button" href="../admin/feedback.php">
                        Manage Feedback
                   </a>
               </article>
               
               <article class="function-card">
                   <h3>Database Explorer</h3>
                   <p>
                       Explore database tables, structures and hashing code.
                   </p>
                   <a class="button" href="../admin/database-explorer.php">
                       Open Database Explorer
                   </a>
                </article>
            </div>

        <?php elseif ($isInputer): ?>

<section class="workspace-card feedback-card">
    <div class="feedback-heading">
        <span class="feedback-icon" aria-hidden="true">&#9993;</span>
        <div>
            <h2>Send Feedback</h2>
            <p>
                Share suggestions, report issues, or let the
                administrator know how we can improve your workspace.
            </p>
        </div>
    </div>

    <?php if (!empty($feedbackSuccess)): ?>
        <div class="feedback-success" role="status">
            <?= htmlspecialchars(
                $feedbackSuccess,
                ENT_QUOTES,
                'UTF-8'
            ) ?>
        </div>
    <?php endif; ?>

    <?php if (!empty($feedbackError)): ?>
        <div class="feedback-error" role="alert">
            <?= htmlspecialchars(
                $feedbackError,
                ENT_QUOTES,
                'UTF-8'
            ) ?>
        </div>
    <?php endif; ?>

    <form method="POST" action="">
        <input
            type="hidden"
            name="csrf_token"
            value="<?= htmlspecialchars(
                $feedbackCsrfToken,
                ENT_QUOTES,
                'UTF-8'
            ) ?>"
        >

        <div class="feedback-field">
            <label for="feedback_category">
                Feedback category
            </label>

            <select
                id="feedback_category"
                name="category"
                required
            >
                <option value="Suggestion">Suggestion</option>
                <option value="Technical Issue">Technical Issue</option>
                <option value="Data Entry Issue">Data Entry Issue</option>
                <option value="Other">Other</option>
            </select>
        </div>

        <div class="feedback-field">
            <label for="feedback_subject">Subject</label>

            <input
                type="text"
                id="feedback_subject"
                name="subject"
                maxlength="150"
                placeholder="Briefly describe your feedback"
                required
            >
        </div>

        <div class="feedback-field">
            <label for="feedback_message">Message</label>

            <textarea
                id="feedback_message"
                name="message"
                rows="5"
                maxlength="5000"
                placeholder="Write your feedback here..."
                required
            ></textarea>
        </div>

        <button type="submit" name="submit_feedback">
            Send Feedback
        </button>
    </form>
</section>


             <?php elseif ($isReviewer): ?>

            <span class="eyebrow">System workspace</span>
            <h2>Reviewer Workspace</h2>
            <p>
                Welcome, <?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?>.
                Your workspace is for reviewing submitted information.
            </p>

            <div class="functions-grid">
    <article class="function-card">
        <h3>Review Submissions</h3>
        <p>Review submitted information.</p>
        <!-- Keep your existing review link here -->
    </article>

    <article class="function-card">
        <h3>Read Feedback</h3>
        <p>Read feedback submitted by Inputers.</p>
        <a class="button" href="../admin/feedback.php">
            View Feedback
        </a>
    </article>
</div>
        <?php elseif ($isAuditor): ?>

            <span class="eyebrow">System workspace</span>
            <h2>Auditor Workspace</h2>
            <p>
                Welcome, <?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?>.
                Your workspace is for reviewing system activity.
            </p>

            <div class="functions-grid">
                <article class="function-card">
                    <h3>Audit and Security Activity</h3>
                    <p>
                        Review system audit records in read-only mode
                        once the audit log access is configured.
                    </p>
                </article>
            </div>

                <?php elseif ($isReviewer): ?>

            <span class="eyebrow">System workspace</span>
            <h2>Reviewer Workspace</h2>
            <p>
                Welcome, <?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?>.
                Your workspace is for reviewing submitted information.
            </p>

            <div class="functions-grid">
                <article class="function-card">
                    <h3>Review Submissions</h3>
                    <p>
                        Review submitted information and make approval
                        decisions when the review workflow is configured.
                    </p>
                </article>
            </div>

        <?php elseif ($isAuditor): ?>

            <span class="eyebrow">System workspace</span>
            <h2>Auditor Workspace</h2>
            <p>
                Welcome, <?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?>.
                Your workspace is for reviewing system activity.
            </p>

            <article class="function-card">
    <h3>Read Feedback</h3>
    <p>
        Read feedback messages for audit and oversight.
        This access is read-only.
    </p>
    <a class="button" href="../admin/feedback.php">
        View Feedback
    </a>
</article>

        <?php else: ?>

            <h2>Access Denied</h2>
            <p>
                Your account role is not recognized.
                Please contact the administrator.
            </p>

        <?php endif; ?>
        <div class="logout-row">
            <a class="button logout" href="logout.php">Log Out</a>
        </div>
    </section>

    <!-- FOOTER -->
    <footer>
        <div>
            <strong>Save Nature, Save Tomorrow</strong>
            <p>Working together for a greener, cleaner future.</p>
        </div>
        <div>
            <strong>Explore</strong>
            <p><a href="#mission">Our Mission</a></p>
            <p><a href="#initiatives">Our Initiatives</a></p>
        </div>
        <div>
            <strong>Account</strong>
            <p><?= htmlspecialchars($username, ENT_QUOTES, 'UTF-8') ?></p>
            <p><?= htmlspecialchars(ucfirst($role), ENT_QUOTES, 'UTF-8') ?></p>
        </div>
        <div>
            <p>&copy; <?= date('Y') ?> Save Nature, Save Tomorrow.</p>
        </div>
    </footer>

</div>
</body>
</html>

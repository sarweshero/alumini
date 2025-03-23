from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from .views import *

urlpatterns = [
    path('login/admin/', AdminLoginView.as_view(), name='login_admin'),
    path('login/staff/', StaffLoginView.as_view(), name='login_staff'),
    path('login/user/', UserLoginView.as_view(), name='login_user'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('signup-otp/', SignupOTPView.as_view(), name='signup-otp'),
    path('Approve-signup/', ApproveSignupView.as_view(), name='signup'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('login-history/', UserLoginHistoryView.as_view(), name='login-history'),
    path('events/<int:pk>', EventDetailView.as_view(), name='events'),
    path('events/', EventView.as_view(), name='events'),
    path('profile/<str:username>', UserProfileView.as_view(), name='profile-views'),
    path('home/', HomePageDataView.as_view(), name='home_page_data'),
    # Jobs endpoints
    path('jobs/', JobListCreateView.as_view(), name='jobs-list-create'),
    path('jobs/<int:pk>/', JobDetailView.as_view(), name='job-detail'),
    path('jobs/<int:job_id>/images/', JobImagesView.as_view(), name='job-images'),  # New endpoint
    path('jobs/<int:job_id>/comments/', JobCommentListCreateView.as_view(), name='job-comment-list-create'),
    path('jobs/comments/<int:pk>/', JobCommentDetailView.as_view(), name='job-comment-detail'),
    path('jobs/<int:job_id>/react/', JobReactionView.as_view(), name='job-react'),
    path('albums/<int:album_id>/images/', AlbumImagesView.as_view(), name='album-images'),
    path('albums/', AlbumDetailView.as_view(), name='albums'),
    # path('albums/<int:pk>/', AlbumImagesView.as_view(), name='albums'),
    path('myposts/', MyPostsView.as_view(), name='myposts'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
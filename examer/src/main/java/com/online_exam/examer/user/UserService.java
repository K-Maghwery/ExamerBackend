package com.online_exam.examer.user;

import com.online_exam.examer.admin.AdminEntity;
import com.online_exam.examer.admin.AdminRepository;
import com.online_exam.examer.exception.AlreadyExsistsException;
import com.online_exam.examer.exception.ResourceNotFoundException;
import com.online_exam.examer.mapper.EntityToDtoMapper;
import com.online_exam.examer.mapper.PageDto;
import com.online_exam.examer.user.request.AddUserRequest;
import com.online_exam.examer.user.request.RecoverUserRequest;
import com.online_exam.examer.user.request.SoftDeleteRequest;
import com.online_exam.examer.user.request.UpdateUserRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService implements IUserService {

    private final UserRepository userRepository;
    private final EntityToDtoMapper entityToDtoMapper;
    private final AdminRepository adminRepository;


    @Transactional
//    @Caching(evict = {
//
//            @CacheEvict(value = "getUsersForExamAndAdmin", allEntries = true)
//    })
    @Override
    public void addUser(AddUserRequest addUserRequest) {

        // Check if user with the same username already exists
       // final String username=addUserRequest.getUserName();
        if (userRepository.existsByAdmin_AdminIdAndUserName(addUserRequest.getAdminId(), addUserRequest.getUserName())&&userRepository.existsByAdmin_AdminIdAndUserNameAndIsDeletedFalse(addUserRequest.getAdminId(), addUserRequest.getUserName())){
            throw new AlreadyExsistsException("The User With This Username Already Exists");
        }

        if (userRepository.existsByAdmin_AdminIdAndUserNameAndIsDeletedTrue(addUserRequest.getAdminId(), addUserRequest.getUserName())){
            throw new AlreadyExsistsException("The User With This Username Already Exists And Deleted You can Recover It Again Or Delete It Permanently");
        }

        // Check if User with the same email already exists
      //  final String email=addUserRequest.getEmail();
        if (userRepository.existsByAdmin_AdminIdAndEmail(addUserRequest.getAdminId(), addUserRequest.getEmail())) {
            throw new AlreadyExsistsException("The User With This Email Already Exists");
        }

        if (userRepository.existsByAdmin_AdminIdAndEmailAndIsDeletedTrue(addUserRequest.getAdminId(), addUserRequest.getEmail())&&userRepository.existsByAdmin_AdminIdAndEmailAndIsDeletedFalse(addUserRequest.getAdminId(), addUserRequest.getEmail())) {
            throw new AlreadyExsistsException("The User With This Email Already Exists And Deleted You can Recover It Again Or Delete It Permanently");
        }
        // Map The Request To UserEntity
        UserEntity newUser = new UserEntity();
        newUser.setUserName(addUserRequest.getUserName());
        newUser.setEmail(addUserRequest.getEmail());
        newUser.setPhone(addUserRequest.getPhone());

        Optional<AdminEntity> optionalAdminEntity = adminRepository.findById(addUserRequest.getAdminId());

        if (optionalAdminEntity.isPresent()) {
            AdminEntity adminEntity = optionalAdminEntity.get();
            newUser.setAdmin(adminEntity);
        } else {
            throw new ResourceNotFoundException("Admin not found to assign to new user");
        }
        // Save To Database
        userRepository.save(newUser);
    }


    @Transactional
//    @Caching(evict = {
//
//            @CacheEvict(value = "getUsersForExamAndAdmin", allEntries = true)
//
//    })
    @Override
    public PageDto<UserDto> softDeleteUser(SoftDeleteRequest softDeleteRequest, Pageable pageable) {

        // Check if the user with the given ID exists or not
        if (!userRepository.existsById(softDeleteRequest.getUserId())) {
            throw new ResourceNotFoundException("User Not Found ");
        }
        UserEntity deletedUser = userRepository.findById(softDeleteRequest.getUserId()).get();

        AdminEntity adminEntity = deletedUser.getAdmin();
        if (!adminRepository.existsById(adminEntity.getAdminId())) {
            throw new ResourceNotFoundException("Admin Not Found");
        }

        // Update isDeleted with True
        deletedUser.setDeleted(true);
        if (deletedUser.getExamSubmission() != null) {
            deletedUser.getExamSubmission().forEach(submission -> submission.setDeleted(true));
        }
        userRepository.save(deletedUser);
        Page<UserEntity> users = userRepository.findByAdminAdminIdAndIsDeletedFalse(adminEntity.getAdminId(),pageable);
        Page<UserDto> usersPageDto = entityToDtoMapper.usersPageToDtoPage(users);
        return new PageDto<>(usersPageDto);
    }

    @Transactional
//    @Caching(evict = {
//
//            @CacheEvict(value = "getUsersForExamAndAdmin", allEntries = true)
//    })
    @Override
    public PageDto<UserDto> updateUser(Long userId, UpdateUserRequest updateUserRequest, Pageable pageable) {
        // Check if the user with the given ID exists or not
        if (!userRepository.existsByUserIdAndIsDeletedFalse(userId)) {
            throw new ResourceNotFoundException("User Not Found");
        }

        // Get UserEntity
        UserEntity userEntity = userRepository.findById(userId).get();
        AdminEntity adminEntity = userEntity.getAdmin();

        // Check if the updated username or email already exists among other users
        if (userRepository.existsByUserNameAndUserIdNot(updateUserRequest.getUserName(), userId)) {
            throw new AlreadyExsistsException("Username already exists.");
        }
        if (userRepository.existsByEmailAndUserIdNot(updateUserRequest.getEmail(), userId)) {
            throw new AlreadyExsistsException("Email already exists.");
        }

        // Update fields
        userEntity.setUserName(updateUserRequest.getUserName());
        userEntity.setEmail(updateUserRequest.getEmail());
        userEntity.setPhone(updateUserRequest.getPhone());

        userRepository.save(userEntity);

        Page<UserEntity> users = userRepository.findByAdminAdminIdAndIsDeletedFalse(adminEntity.getAdminId(), pageable);

        Page<UserDto> usersPageDto = entityToDtoMapper.usersPageToDtoPage(users);

        // Wrap the Page<UserDto> into PageDto<UserDto> to return only necessary data
        return new PageDto<>(usersPageDto);
    }

    @Transactional
    @Override
    public UserDto getUserById(Long userId) {
        // Check if the user with the given ID exists or not
        if (!userRepository.existsByUserIdAndIsDeletedFalse(userId)) {
            throw new ResourceNotFoundException("User Not Found");
        }
        UserEntity existsUser = userRepository.findById(userId).get();
        return entityToDtoMapper.userToDto(existsUser);
    }


    @Transactional
  //  @Cacheable(value = "getDeletedUserByAdminId", key = "#examId + '-' + #adminId + '-' + #pageable.pageNumber + '-' + #pageable.pageSize")
    @Override
    public PageDto<UserDto> getDeletedUsersByAdminId(Long adminId,Pageable pageable){
        Page<UserEntity>deletedUsers = userRepository.findByAdminAdminIdAndIsDeletedTrue(adminId,pageable);
        Page<UserDto> usersPageDto = entityToDtoMapper.usersPageToDtoPage(deletedUsers);
        return new PageDto<>(usersPageDto);
    }

    @Transactional
//    @Caching(evict = {
//
//
//            @CacheEvict(value = "getUsersForExamAndAdmin", allEntries = true)
//    })
    @Override
    public PageDto<UserDto> hardDeleteByUserId(Long UserId, Pageable pageable) {
        UserEntity userEntity = userRepository.findById(UserId).get();
        AdminEntity adminEntity = userEntity.getAdmin();
        Long adminId = adminEntity.getAdminId();
        userRepository.delete(userEntity);
        Page<UserEntity>deletedUsers = userRepository.findByAdminAdminIdAndIsDeletedTrue(adminId,pageable);
        Page<UserDto> usersPageDto = entityToDtoMapper.usersPageToDtoPage(deletedUsers);
        return new PageDto<>(usersPageDto);
    }
    @Transactional
//    @Caching(evict = {
//
//
//            @CacheEvict(value = "getUsersForExamAndAdmin", allEntries = true)
//    })
    @Override
    public PageDto<UserDto> recoverUser(RecoverUserRequest recoverUserRequest, Pageable pageable) {
        UserEntity recoveredUser = userRepository.findById(recoverUserRequest.getUserId()).get();

        if (recoveredUser.getExamSubmission() != null) {
            recoveredUser.getExamSubmission().forEach(submission -> submission.setDeleted(false));
        }

        recoveredUser.setDeleted(false);
        userRepository.save(recoveredUser);
        AdminEntity adminEntity = recoveredUser.getAdmin();
        Page<UserEntity> users = userRepository.findByAdminAdminIdAndIsDeletedTrue(adminEntity.getAdminId(),pageable);
        Page<UserDto> usersPageDto = entityToDtoMapper.usersPageToDtoPage(users);
        return new PageDto<>(usersPageDto);
    }

    @Transactional(readOnly = true)
    @Override
    public PageDto<UserDto> findByAdminId(Long adminId,Pageable pageable) {
//        List<UserEntity> usersOfAdmin =userRepository.findByAdminAdminId(adminId);
//        return entityToDtoMapper.usersToDtoList(usersOfAdmin);
        // Fetch the all user with pagination
        Page<UserEntity> users = userRepository.findByAdminAdminIdAndIsDeletedFalse(adminId, PageRequest.of(pageable.getPageNumber(), pageable.getPageSize(), Sort.by("userName").ascending()));

        // Convert the Page<UserEntity> to Page<UserDto>
        Page<UserDto> usersPageDto = entityToDtoMapper.usersPageToDtoPage(users);

        // Wrap the Page<UserDto> into PageDto<UserDto> to return only necessary data
        return new PageDto<>(usersPageDto);
    }

    @Transactional(readOnly = true)
   // @Cacheable(value = "findUsersByAdminIdAndStatusFalse", key = "#examId + '-' + #adminId + '-' + #pageable.pageNumber + '-' + #pageable.pageSize")
    @Override
    public PageDto<UserDto> findUsersByAdminIdAndStatusFalse(Long examId,Long adminId,Pageable pageable){

        Page<UserEntity> users = userRepository.findUsersByExamIdAndSubmissionStatus(examId,adminId,pageable);
        // Convert the Page<UserEntity> to Page<UserDto>
        Page<UserDto> usersPageDto = entityToDtoMapper.usersPageToDtoPage(users);

        // Wrap the Page<UserDto> into PageDto<UserDto> to return only necessary data
        return new PageDto<>(usersPageDto);
    }

    @Transactional(readOnly = true)
  //  @Cacheable(value = "findUsersByAdminIdAndNotAssigned", key = "#examId + '-' + #adminId")
    @Override
    public List<UserDto> findUsersByAdminIdAndNotAssigned(Long examId,Long adminId){

        List<UserEntity> users = userRepository.findUsersByAdminIdWithoutExamSubmission(examId,adminId);
        return entityToDtoMapper.usersToDtoList(users);
    }

    /****************** Not Used ******************/

//    @Transactional(readOnly = true)
//    @Override
//    public PageDto<UserDto> getAllUsers(Pageable pageable){
//
//        // Fetch the all questions with pagination
//        Page<UserEntity> users = userRepository.findByIsDeletedFalse(pageable);
//
//        // Convert the Page<UserEntity> to Page<UserDto>
//        Page<UserDto> usersPageDto = entityToDtoMapper.usersPageToDtoPage(users);
//
//        // Wrap the Page<UserDto> into PageDto<UserDto> to return only necessary data
//        return new PageDto<>(usersPageDto);
//    }
//
//
//    @Transactional(readOnly = true)
//    @Override
//    public List<UserDto> findByAdminAdminUserName(String adminUsername) {
//        List<UserEntity> usersOfAdmin =userRepository.findByAdminAdminUserNameAndIsDeletedFalse(adminUsername);
//        return entityToDtoMapper.usersToDtoList(usersOfAdmin);
//    }


}
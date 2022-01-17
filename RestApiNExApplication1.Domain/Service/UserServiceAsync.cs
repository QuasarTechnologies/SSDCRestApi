using AutoMapper;
using Microsoft.Data.SqlClient;
using RestApiNExApplication1.Entity;
using RestApiNExApplication1.Entity.UnitofWork;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;

namespace RestApiNExApplication1.Domain.Service
{
    public class UserServiceAsync<Tv, Te> : GenericServiceAsync<Tv, Te>
                                                where Tv : UserViewModel
                                                where Te : User
    {
        //DI must be implemented specific service as well beside GenericAsyncService constructor
        public UserServiceAsync(IUnitOfWork unitOfWork, IMapper mapper)
        {
            if (_unitOfWork == null)
                _unitOfWork = unitOfWork;
            if (_mapper == null)
                _mapper = mapper;
        }

        //add here any custom service method or override genericasync service method
        //...

        /// <summary>
        /// 
        /// These service calls are examples of stored procedure use in Apincore REAT API serice
        /// READbyStoredProcedure(sql, parameters)
        /// CUDbyStoredProcedure(sql, parameters)
        /// 
        /// </summary>
        /// 

        //stored procedure READ 
        //note:sp params must be in the same order like in sp
        public async Task<IEnumerable<UserViewModel>> GetUsersByName(string firstName, string lastName)
        {
            var parameters = new[] {
            new SqlParameter("@FirstName", SqlDbType.VarChar) { Direction = ParameterDirection.Input, Value = firstName },
            new SqlParameter("@LastName", SqlDbType.VarChar) { Direction = ParameterDirection.Input, Value = lastName }
            };
            var sql = "EXEC [dbo].[prGetUserByFirstandLastName] @FirstName, @LastName";

            var users = await _unitOfWork.GetRepositoryAsync<User>().READbyStoredProcedure(sql, parameters);
            return _mapper.Map<IEnumerable<UserViewModel>>(source: users);
        }


        //stored procedure CREATE UPDATE DELETE 
        //note:sp params must be in the same order like in sp
        public async Task<int> UpdateEmailByUsername(string username, string email)
        {
            var parameters = new[] {
                new SqlParameter("@UserName", SqlDbType.VarChar) { Direction = ParameterDirection.Input, Value = username },
                new SqlParameter("@Email", SqlDbType.VarChar) { Direction = ParameterDirection.Input, Value = email }
                };
            string sql = "EXEC [dbo].[prUpdateEmailByUsername] @UserName, @Email";

            int records = await _unitOfWork.GetRepositoryAsync<User>().CUDbyStoredProcedure(sql, parameters);
            return records;
        }


    }

}
